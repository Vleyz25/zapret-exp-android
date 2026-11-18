package ru.zapret.exp;

import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;

/**
 * Один TCP-поток: конечная точка туннеля в пользовательском пространстве + реальное
 * соединение через сокет, который не попадает в туннель (наш пакет исключён из
 * маршрутов VpnService).
 *
 * Приложение телефона считает, что говорит с настоящим сервером: мы отвечаем SYN-ACK,
 * подтверждаем его данные и отдаём ответы сервера своими сегментами. Именно поэтому
 * появляется возможность переформатировать исходящий запрос (фрагментация ClientHello) —
 * то же на ПК делает winws.exe через WinDivert.
 *
 * Два направления и два «окна»:
 *   вверх (клиент -> сервер) — очередь queue; переполнение = объявляем окно 0;
 *   вниз (сервер -> клиент) — очередь outQueue; отправляем не больше окна клиента.
 *
 * Окна масштабированы (RFC 7323): без window scaling потолок приёма — 65535 байт на
 *один круг задержки, то есть порядка 1 МБ/с на мобильном RTT, и скорость интернета упиралась бы в нас.
 * Мы объявляем wscale=4 (до 1 МБ), а окно клиента умножаем на его собственный scale из
 * опций SYN — иначе сами себе ограничивали отдачу в 64 КБ.
 */
public final class TcpFlow {

    private static final String TAG = "TcpFlow";
    private static final int OUR_SCALE = 4;              // наше окно: 65535 << 4 ~= 1 МБ
    private static final int MAX_QUEUE = 1 << 20;        // вверх, 1 МБ
    private static final int MAX_OUT = 8 << 20;          // вниз, 8 МБ
    private static final long IDLE_MS = 300_000;
    private static final long BLOCKED_MS = 45_000;
    private static final int CONNECT_MS = 8000;
    private static final int READ_WAIT_MS = 4000;
    /** Сколько молча переживаем «хвосты» закрытого соединения, чтобы не слать RST. */
    public static final long GRACE_MS = 15_000;

    /** То, что поток требует от сервиса. */
    public interface Host {
        void protectFd(FileDescriptor fd) throws Exception;
        void toTun(byte[] packet);
        Profile profile();
        Stats stats();
    }

    /** Кусок данных «вниз» с незавершённой отправкой. */
    private static final class Piece {
        final byte[] b;
        int off;
        Piece(byte[] b, int off) { this.b = b; this.off = off; }
        int left() { return b.length - off; }
    }

    private final Host host;
    private final Bits.Pkt tmpl;          // пакет клиента: адреса/порты для разворота ответа
    private final byte[] srvAddr;
    private final int srvPort, cliPort;
    private final boolean v6;
    private final String key;
    private String peer;

    private final long iss;
    // rcvNxt пишет только читающий поток туннеля, sndNxt — только рабочий поток;
    // volatile нужен, потому что оба потока читают значение друг друга.
    private volatile long rcvNxt, sndNxt;
    private final int peerScale;
    private volatile long peerWindow;                     // уже масштабированное
    private volatile long peerAcked;

    private final ArrayDeque<byte[]> queue = new ArrayDeque<>();       // клиент -> сервер
    private final ArrayDeque<Piece> outQueue = new ArrayDeque<>();     // сервер -> клиент
    private int queued, outQueued;
    private final Object lock = new Object();

    private Thread worker;
    private Socket sock;
    private OutputStream out;
    private InputStream in;
    private volatile boolean stopped, firstSent, clientDone, eofFromServer, ready;
    private volatile long lastActivity = System.currentTimeMillis();
    private volatile long closedAt;
    private long blockedSince;
    private long lastSynAckAt;

    public TcpFlow(Host host, Bits.Pkt syn, String key) {
        this.host = host;
        this.tmpl = syn;
        this.key = key;
        this.v6 = syn.family == Bits.V6;
        this.srvAddr = syn.dst;
        this.srvPort = syn.dport;
        this.cliPort = syn.sport;
        this.peer = Bits.addrToString(syn.dst) + ":" + syn.dport;
        this.iss = (long) (Math.random() * 0xFFFFFF) + 0x100000L;
        this.rcvNxt = (syn.seq + syn.dataLen + (isSet(syn.flags, Bits.SYN) ? 1 : 0)) & 0xFFFFFFFFL;
        this.sndNxt = (this.iss + 1) & 0xFFFFFFFFL;
        this.peerAcked = this.iss;                        // клиент ещё ничего не подтвердил
        this.peerScale = Math.max(0, Math.min(14, syn.wscale));
        // пока не пришло ни одного ACK, берём максимум, который клиент мог объявить
        this.peerWindow = Math.min(16L << 20, 65535L << peerScale);
    }

    private static boolean isSet(int flags, int f) { return (flags & f) != 0; }

    public void start() {
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                TcpFlow.this.run();
            }
        }, "tcp-" + peer);
        worker.setDaemon(true);
        worker.start();
    }

    private volatile int dlMss;

    /**
     * Размер сегмента: по умолчанию под текущий MTU туннеля (он подобран под реальный
     * линк), а если в правиле задан mss — им режем ответы сервера. Байты не меняются,
     * меняется нарезка: ровно то, для чего на ПК служит --dpi-desync-split-pos.
     */
    private int mss() {
        int d = dlMss;
        if (d >= 88) return d;
        int m = ZapretService.MTU - (v6 ? 60 : 40);
        return m < 536 ? 536 : m;
    }

    /** Какое окно объявляем клиенту (в сыром виде, он умножит на 1<<OUR_SCALE). */
    private int advWindow() {
        long avail;
        synchronized (lock) { avail = MAX_QUEUE - queued; }
        if (avail < 0) avail = 0;
        return (int) Math.min(0xFFFFL, avail >> OUR_SCALE);
    }

    // ---------------------------------------------------------------- приём из туннеля

    /** Вызывается из читающего потока туннеля. */
    public void onClientPacket(Bits.Pkt p) {
        lastActivity = System.currentTimeMillis();

        if (isSet(p.flags, Bits.RST)) {
            host.stats().log("RST от клиента -> " + peer);
            close(true);
            return;
        }

        // повторный SYN (клиент не получил SYN-ACK) — повторяем свой SYN-ACK, иначе
        // приложение упрётся в таймаут и закроет соединение с нашей стороны
        if (isSet(p.flags, Bits.SYN) && !isSet(p.flags, Bits.ACK)) {
            if (ready && System.currentTimeMillis() - lastSynAckAt > 400) sendSynAck();
            return;
        }

        // что клиент подтвердил и какое окно объявляет
        peerAcked = Window.advanceAcked(peerAcked, p.ackNum);
        peerWindow = Math.min(16L << 20, (p.window & 0xFFFFL) << peerScale);

        if (p.dataLen > 0) {
            long seq = p.seq & 0xFFFFFFFFL;
            long end = (seq + p.dataLen) & 0xFFFFFFFFL;
            int skip = 0, take = p.dataLen;
            if (!Window.serialAfter(end, rcvNxt) && end != rcvNxt) {
                skip = p.dataLen;                                   // целиком старые данные
            } else if (!Window.serialAfter(seq, rcvNxt) && seq != rcvNxt) {
                skip = (int) ((rcvNxt - seq) & 0xFFFFFFFFL);        // часть уже принята
                take = p.dataLen - skip;
            }
            if (take > 0) {
                byte[] chunk = Bits.slice(p.buf, p.dataOff + skip, take);
                boolean accepted;
                synchronized (lock) {
                    accepted = queued + take <= MAX_QUEUE;
                    if (accepted) {
                        queue.add(chunk);
                        queued += take;
                        host.stats().bytesUp.addAndGet(take);
                    }
                    lock.notifyAll();
                }
                if (!accepted) host.stats().dropped.incrementAndGet();
                rcvNxt = (seq + skip + take) & 0xFFFFFFFFL;
            }
        }

        if (isSet(p.flags, Bits.FIN)) clientDone = true;

        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK, advWindow(), null, 0, 0, 0));

        // возможно, клиент открыл окно — есть чем разблокировать отдачу
        synchronized (lock) { lock.notifyAll(); }
    }

    private void sendSynAck() {
        lastSynAckAt = System.currentTimeMillis();
        host.toTun(Bits.buildTcp(tmpl, iss, rcvNxt, Bits.SYN | Bits.ACK, advWindow(),
                null, 0, 0, mss(), OUR_SCALE));
    }

    // ---------------------------------------------------------------- рабочий поток

    private void run() {
        try {
            if (v6 && !ZapretService.IPV6_UP) {
                // без IPv6-канала вверх соединение туда обречено: отвечаем RST сразу,
                // а не держим клиента 8 секунд на таймауте
                host.stats().log("нет IPv6 вверх: " + peer + " отклонено");
                host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.RST, 0, null, 0, 0, 0));
                return;
            }
            sock = new Socket();
            // Каждый write() должен уйти сразу одним сегментом, иначе фрагментация
            // ClientHello превратится в «ядро само соберёт как хочет».
            try { sock.setTcpNoDelay(true); } catch (Exception ignored) { }
            try { sock.setTrafficClass(0x10); } catch (Exception ignored) { }
            try { sock.setSoTimeout(READ_WAIT_MS); } catch (Exception ignored) { }
            // явный таймаут: иначе мёртвый адрес держит этот поток две минуты, а приложение
            // в это время показывает «бесконечную загрузку»
            sock.connect(new InetSocketAddress(InetAddress.getByAddress(srvAddr), srvPort),
                    CONNECT_MS);
            out = sock.getOutputStream();
            in = sock.getInputStream();
            ready = true;
            sendSynAck();
            host.stats().log("TCP -> " + peer + " установлен");

            byte[] rbuf = new byte[16384];

            while (!stopped) {
                // 1) данные клиента -> серверу (первый запрос — с десинхронизацией)
                byte[] chunk;
                synchronized (lock) { chunk = queue.peekFirst(); }
                if (chunk != null) {
                    if (!firstSent) {
                        String proto = Hello.protocolOf(chunk, 0, chunk.length);
                        String hostName = null;
                        if ("tls".equals(proto)) hostName = Hello.sni(chunk, 0, chunk.length);
                        else if ("http".equals(proto)) hostName = Hello.httpHost(chunk, 0, chunk.length);
                        Config.Rule rule = host.profile().matchTcp(srvPort, hostName);
                        if (hostName != null && !peer.contains("(")) {
                            peer = peer + " (" + hostName + ")";
                        }
                        Desync.sendFirst(out, v6,
                                Desync.serverAddress(srvAddr, srvPort),
                                chunk, 0, chunk.length, rule, proto, host.stats(), peer);
                        firstSent = true;
                        // mss из правила: с этого момента ответы сервера отдаём
                        // более мелкими сегментами (тот же байтовый поток, другая нарезка)
                        if (rule != null && rule.mss >= 88) {
                            dlMss = rule.mss;
                            host.stats().log("сегменты ответа: " + dlMss + " байт [" + rule.name + "]");
                        }
                    } else {
                        out.write(chunk, 0, chunk.length);
                        out.flush();
                    }
                    synchronized (lock) {
                        queue.pollFirst();
                        queued -= chunk.length;
                        lock.notifyAll();
                    }
                    continue;   // сразу к следующему куску, не дожидаясь чтения
                }

                if (clientDone && queued == 0 && !eofFromServer) {
                    try { sock.shutdownOutput(); } catch (Exception ignored) { }
                    clientDone = false;
                }

                // 2) отдать клиенту то, что уже прочитано и ждёт своего окна
                pump();

                // 3) почитать сервера, если есть куда складывать
                boolean room;
                synchronized (lock) { room = outQueued < MAX_OUT; }
                if (room) {
                    int n;
                    try {
                        n = in.read(rbuf, 0, Math.min(rbuf.length, mss() * 12));
                    } catch (SocketTimeoutException te) {
                        n = -2;                     // просто тихо, не обрыв
                    }
                    if (n > 0) {
                        enqueueOut(rbuf, 0, n);
                        lastActivity = System.currentTimeMillis();
                        continue;
                    }
                    if (n == 0) {
                        // ноль не бывает у InputStream.read(len>0), но на всякий случай
                    } else if (n == -1) {
                        eofFromServer = true;
                        pump();
                        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.FIN | Bits.ACK,
                                advWindow(), null, 0, 0, 0));
                        break;
                    }
                }

                // 4) ничего не происходит: ждём либо данные, либо ACK (окно), либо таймаут
                if (hasPendingWork()) {
                    synchronized (lock) {
                        try { lock.wait(100); } catch (InterruptedException ignored) { }
                    }
                } else {
                    synchronized (lock) {
                        try { lock.wait(200); } catch (InterruptedException ignored) { }
                    }
                }

                if (blockedSince != 0 && System.currentTimeMillis() - blockedSince > BLOCKED_MS) {
                    host.stats().log("поток TCP " + peer + " закрыт: клиент не открыл окно");
                    break;
                }
                if (System.currentTimeMillis() - lastActivity > IDLE_MS) {
                    host.stats().log("поток TCP " + peer + " закрыт по простою");
                    break;
                }
            }
        } catch (Exception e) {
            if (!stopped) {
                if (ready) {
                    // соединение жило — обрыв пришёл от сервера. Закрываем аккуратно FINом,
                    // чтобы приложение не показало «соединение сброшено» на ровном месте.
                    host.stats().log("сервер оборвал " + peer + ": " + reason(e));
                    try {
                        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.FIN | Bits.ACK,
                                advWindow(), null, 0, 0, 0));
                    } catch (Exception ignored) { }
                } else {
                    host.stats().log("нет связи с " + peer + " (" + (v6 ? "IPv6" : "IPv4")
                            + "): " + reason(e));
                    Log.d(TAG, "connect failed", e);
                    try {
                        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.RST, 0, null, 0, 0, 0));
                    } catch (Exception ignored) { }
                }
            }
        } finally {
            close(false);
        }
    }

    private static String reason(Exception e) {
        String m = e.getMessage();
        if (m == null || m.isEmpty()) m = e.getClass().getSimpleName();
        Throwable c = e.getCause();
        if (c != null && c.getMessage() != null && !c.getMessage().isEmpty()) m += " <- " + c.getMessage();
        return m;
    }

    private boolean hasPendingWork() {
        synchronized (lock) {
            return !queue.isEmpty() || !outQueue.isEmpty();
        }
    }

    /** Кладём ответ сервера в очередь «вниз» кусками по MSS. */
    private void enqueueOut(byte[] buf, int off, int len) {
        int m = mss();
        int pos = off, end = off + len;
        synchronized (lock) {
            while (pos < end) {
                int n = Math.min(m, end - pos);
                byte[] piece = Bits.slice(buf, pos, n);
                outQueue.add(new Piece(piece, 0));
                outQueued += n;
                pos += n;
            }
        }
        pump();
    }

    /**
     * Отдаём клиенту ровно столько, сколько он разрешил: не больше объявленного окна.
     * Если окно закрыто — запоминаем момент, чтобы не висеть вечно.
     */
    private void pump() {
        int m = mss();
        while (!stopped) {
            Piece head;
            synchronized (lock) { head = outQueue.peekFirst(); }
            if (head == null) {
                blockedSince = 0;
                return;
            }
            long free = Window.allowed(sndNxt, peerAcked, peerWindow);
            if (free <= 0) {
                if (blockedSince == 0) blockedSince = System.currentTimeMillis();
                return;
            }
            int n = (int) Math.min(head.left(), free);
            host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK | Bits.PSH, advWindow(),
                    head.b, head.off, n, 0));
            head.off += n;
            sndNxt = (sndNxt + n) & 0xFFFFFFFFL;
            host.stats().bytesDown.addAndGet(n);
            blockedSince = 0;
            if (head.left() == 0) {
                synchronized (lock) {
                    outQueue.pollFirst();
                    outQueued -= head.b.length;
                }
            }
        }
    }

    public void close(boolean hard) {
        if (stopped) return;
        stopped = true;
        closedAt = System.currentTimeMillis();
        synchronized (lock) { lock.notifyAll(); }
        if (sock != null) {
            try { sock.close(); } catch (IOException ignored) { }
            sock = null;
        }
        // Из таблицы потоков нас убирает сервис: ему нужен closedAt, чтобы не
        // обрывать запоздалые ACK/FIN клиента через RST.
    }

    public String key() { return key; }
    public boolean isStopped() { return stopped; }
    public long closedAt() { return closedAt; }
}
