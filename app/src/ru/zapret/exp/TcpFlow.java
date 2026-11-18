package ru.zapret.exp;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import java.io.FileDescriptor;
import java.net.InetAddress;
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
 * два направления, два «окна»:
 *   вверх (клиент -> сервер)  — очередь queue, переполнение = объявляем окно 0;
 *   вниз (сервер -> клиент)  — очередь outQueue, отправляем не больше окна клиента
 *                              (Window.allowed), иначе данные ушли бы сверх window,
 *                              клиент бы их отбросил, а повторной передачи у нас нет.
 */
public final class TcpFlow {

    private static final String TAG = "TcpFlow";
    private static final int MSS = 1360;
    private static final int MAX_QUEUE = 1 << 20;       // вверх, 1 МБ
    private static final int MAX_OUT = 8 << 20;         // вниз, 8 МБ
    private static final long IDLE_MS = 300_000;
    /** Сколько молча переживаем «хвосты» закрытого соединения, чтобы не слать RST. */
    public static final long GRACE_MS = 15_000;
    /** Сколько ждём, пока клиент откроет окно, прежде чем признать поток мёртвым. */
    private static final long BLOCKED_MS = 45_000;

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

    private final long iss, irs;
    // rcvNxt пишет только читающий поток туннеля, sndNxt — только рабочий поток;
    // volatile нужен, потому что оба потока читают значение друг друга.
    private volatile long rcvNxt, sndNxt;
    private volatile long peerWindow = 65535;
    private volatile long peerAcked;

    private final ArrayDeque<byte[]> queue = new ArrayDeque<>();       // клиент -> сервер
    private final ArrayDeque<Piece> outQueue = new ArrayDeque<>();     // сервер -> клиент
    private int queued, outQueued;
    private final Object lock = new Object();

    private Thread worker;
    private FileDescriptor fd;
    private volatile boolean stopped, firstSent, clientDone, eofFromServer, ready;
    private volatile long lastActivity = System.currentTimeMillis();
    private volatile long closedAt;
    private long blockedSince;

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
        this.irs = syn.seq;
        this.rcvNxt = (syn.seq + syn.dataLen + (isSet(syn.flags, Bits.SYN) ? 1 : 0)) & 0xFFFFFFFFL;
        this.sndNxt = (this.iss + 1) & 0xFFFFFFFFL;
        this.peerAcked = this.iss;                       // клиент ещё ничего не подтвердил
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

    // ---------------------------------------------------------------- приём из туннеля

    /** Вызывается из читающего потока туннеля. */
    public void onClientPacket(Bits.Pkt p) {
        lastActivity = System.currentTimeMillis();

        if (isSet(p.flags, Bits.RST)) {
            host.stats().log("RST от клиента -> " + peer);
            close(true);
            return;
        }

        // что клиент подтвердил и какое окно объявляет
        peerAcked = Window.advanceAcked(peerAcked, p.ackNum);
        peerWindow = p.window;

        // Чистый SYN: подтверждаем его SYN-ACK из рабочего потока, здесь молчим,
        // иначе клиент получил бы ACK раньше, чем SYN-ACK.
        if (isSet(p.flags, Bits.SYN) && p.dataLen == 0) return;

        if (p.dataLen > 0) {
            long seq = p.seq & 0xFFFFFFFFL;
            long end = (seq + p.dataLen) & 0xFFFFFFFFL;
            int skip = 0;
            int take = p.dataLen;
            if (seqBefore(end, rcvNxt)) {
                skip = p.dataLen;                       // целиком старые данные (ретрансмиссия)
            } else if (seqBefore(seq, rcvNxt)) {
                skip = (int) ((rcvNxt - seq) & 0xFFFFFFFFL);  // часть уже принята
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

        // подтверждаем всё принятое; окно = сколько ещё готовы принять наверх
        int advWindow = (int) Math.max(0, Math.min(0xFFFF, MAX_QUEUE - queued));
        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK, advWindow, null, 0, 0, 0));

        // возможно, клиент открыл окно — есть чем разблокировать отдачу
        synchronized (lock) { lock.notifyAll(); }
    }

    // ---------------------------------------------------------------- рабочий поток

    private void run() {
        try {
            fd = Os.socket(v6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_STREAM, 0);
            host.protectFd(fd);
            Os.connect(fd, InetAddress.getByAddress(srvAddr), srvPort);
            ready = true;
            // SYN-ACK: MSS объявляем, чтобы клиент не слал сегменты больше нашего MTU
            host.toTun(Bits.buildTcp(tmpl, iss, rcvNxt, Bits.SYN | Bits.ACK,
                    (int) Math.min(0xFFFF, MAX_QUEUE), null, 0, 0, MSS));
            host.stats().log("TCP -> " + peer + " установлен");

            StructPollfd pollfd = new StructPollfd();
            pollfd.fd = fd;
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
                        Desync.sendFirst(fd, v6, Desync.serverAddress(srvAddr, srvPort),
                                chunk, 0, chunk.length, rule, proto, host.stats(), peer);
                        firstSent = true;
                    } else {
                        Desync.writeAll(fd, chunk, 0, chunk.length);
                    }
                    synchronized (lock) {
                        queue.pollFirst();
                        queued -= chunk.length;
                    }
                    continue;   // сразу к следующему куску, не дожидаясь poll
                }

                if (clientDone && queued == 0 && !eofFromServer) {
                    try { Os.shutdown(fd, OsConstants.SHUT_WR); } catch (Exception ignored) { }
                    clientDone = false;
                }

                // 2) отдать клиенту то, что уже прочитано от сервера и ждёт своего окна
                pump();

                // 3) почитать сервера, если есть куда складывать
                boolean room;
                synchronized (lock) { room = outQueued < MAX_OUT; }
                pollfd.events = (short) (room ? OsConstants.POLLIN : 0);
                int pr = Os.poll(new StructPollfd[]{pollfd}, 200);
                if (pr > 0 && (pollfd.revents & (OsConstants.POLLIN | OsConstants.POLLHUP)) != 0 && room) {
                    int n = Os.read(fd, rbuf, 0, Math.min(rbuf.length, MSS * 4));
                    if (n <= 0) {
                        eofFromServer = true;
                        pump();          // сначала доотдаём накопленное
                        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.FIN | Bits.ACK,
                                (int) Math.min(0xFFFF, peerWindow), null, 0, 0, 0));
                        break;
                    }
                    enqueueOut(rbuf, 0, n);
                    continue;
                }

                // 4) ничего не происходит: ждём либо данных, либо ACK (окна), либо таймаута
                if (hasPendingWork()) {
                    synchronized (lock) {
                        try { lock.wait(100); } catch (InterruptedException ignored) { }
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
                host.stats().log("ошибка TCP " + peer + ": " + e);
                Log.d(TAG, "flow error", e);
                try {
                    host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.RST, 0, null, 0, 0, 0));
                } catch (Exception ignored) { }
            }
        } finally {
            close(false);
        }
    }

    private boolean hasPendingWork() {
        synchronized (lock) {
            return !queue.isEmpty() || !outQueue.isEmpty();
        }
    }

    /** Кладём ответ сервера в очередь «вниз» кусками по MSS. */
    private void enqueueOut(byte[] buf, int off, int len) {
        int pos = off, end = off + len;
        synchronized (lock) {
            while (pos < end) {
                int n = Math.min(MSS, end - pos);
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
        while (!stopped) {
            Piece head;
            synchronized (lock) { head = outQueue.peekFirst(); }
            if (head == null) {
                blockedSince = 0;
                return;
            }
            long free = Window.allowed(sndNxt, peerAcked, (int) peerWindow);
            if (free <= 0) {
                if (blockedSince == 0) blockedSince = System.currentTimeMillis();
                return;
            }
            int n = (int) Math.min(head.left(), free);
            int advWindow = (int) Math.max(0, Math.min(0xFFFF, MAX_QUEUE - queued));
            host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK | Bits.PSH, advWindow,
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

    /** Сравнение номеров последовательности по модулю 2^32. */
    private static boolean seqBefore(long a, long b) {
        return !Window.serialAfter(a, b) && a != b;
    }

    public void close(boolean hard) {
        if (stopped) return;
        stopped = true;
        closedAt = System.currentTimeMillis();
        synchronized (lock) { lock.notifyAll(); }
        if (fd != null) {
            try { Os.close(fd); } catch (Exception ignored) { }
            fd = null;
        }
        // Из таблицы потоков нас убирает сервис: ему нужен closedAt, чтобы не
        // обрывать запоздалые ACK/FIN клиента через RST.
    }

    public String key() { return key; }
    public boolean isStopped() { return stopped; }
    public long closedAt() { return closedAt; }
}
