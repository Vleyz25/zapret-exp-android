package ru.zapret.exp;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.util.ArrayDeque;

/**
 * Один TCP-поток: пользовательская конечная точка туннеля + реальное соединение через
 * защищённый сокет (VpnService.protect), чтобы наш собственный трафик снова не попал
 * в туннель.
 *
 * Ядро телефона считает, что общается с настоящим сервером: мы отвечаем ему SYN-ACK,
 * подтверждаем данные и отдаём ответы сервера собственными сегментами. Отсюда и
 * появляется возможность переформатировать исходящий запрос (фрагментация, фейки) —
 * ровно то, на ПК делает winws.exe через WinDivert.
 */
public final class TcpFlow {

    private static final String TAG = "TcpFlow";
    private static final int MSS = 1360;
    private static final int MAX_QUEUE = 1 << 20;      // 1 МБ на поток
    private static final long IDLE_MS = 300_000;
    /** Сколько молча переживаем «хвосты» закрытого соединения, чтобы не слать RST. */
    public static final long GRACE_MS = 15_000;

    /** То, что поток требует от сервиса. */
    public interface Host {
        void protectFd(FileDescriptor fd) throws Exception;
        void toTun(byte[] packet);
        Profile profile();
        Stats stats();
    }

    private final Host host;
    private final Bits.Pkt tmpl;          // пакет клиента: адреса/порты для разворота ответа
    private final byte[] srvAddr;
    private final int srvPort, cliPort;
    private final boolean v6;
    private final String key;
    private String peer;

    private long iss, irs;
    // rcvNxt пишет только читающий поток туннеля, sndNxt — только рабочий поток;
    // volatile нужен, потому что оба потока читают значение друг друга.
    private volatile long rcvNxt, sndNxt;
    private volatile long peerWindow = 65535;

    private final ArrayDeque<byte[]> queue = new ArrayDeque<>();
    private int queued;
    private final Object lock = new Object();

    private Thread worker;
    private FileDescriptor fd;
    private volatile boolean stopped, firstSent, clientDone, eofFromServer, ready;
    private volatile long lastActivity = System.currentTimeMillis();
    private volatile long closedAt;

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

    /** Вызывается из читающего потока туннеля. */
    public void onClientPacket(Bits.Pkt p) {
        lastActivity = System.currentTimeMillis();
        if (isSet(p.flags, Bits.RST)) {
            host.stats().log("RST от клиента -> " + peer);
            close(true);
            return;
        }
        if (p.window >= 0) peerWindow = p.window;

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
                synchronized (lock) {
                    if (queued + take <= MAX_QUEUE) {
                        queue.add(chunk);
                        queued += take;
                        host.stats().bytesUp.addAndGet(take);
                    } else {
                        host.stats().dropped.incrementAndGet();
                    }
                }
                rcvNxt = (seq + skip + take) & 0xFFFFFFFFL;
            }
            synchronized (lock) { lock.notifyAll(); }
        }

        if (isSet(p.flags, Bits.FIN)) clientDone = true;

        // подтверждаем всё принятое; окно = сколько ещё готовы принять
        int window = (int) Math.max(0, Math.min(0xFFFF, MAX_QUEUE - queued));
        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK, window, null, 0, 0, 0));
    }

    private void run() {
        try {
            fd = Os.socket(v6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_STREAM, 0);
            host.protectFd(fd);
            Os.connect(fd, InetAddress.getByAddress(srvAddr), srvPort);
            ready = true;
            // SYN-ACK клиенту: MSS-опцию добавляем, чтобы клиент не слал сегменты больше нашего MTU
            host.toTun(Bits.buildTcp(tmpl, iss, rcvNxt, Bits.SYN | Bits.ACK,
                    (int) Math.min(0xFFFF, MAX_QUEUE), null, 0, 0, MSS));
            host.stats().log("поток TCP -> " + peer + " установлен");

            StructPollfd pollfd = new StructPollfd();
            pollfd.fd = fd;
            byte[] rbuf = new byte[16384];

            while (!stopped) {
                boolean wroteSomething = false;

                // 1) данные клиента -> серверу (первый запрос — с десинхронизацией)
                byte[] chunk = null;
                synchronized (lock) {
                    chunk = queue.peekFirst();
                }
                if (chunk != null && !stopped) {
                    Config.Rule rule = null;
                    if (!firstSent) {
                        String proto = Hello.protocolOf(chunk, 0, chunk.length);
                        String hostName = null;
                        if ("tls".equals(proto)) hostName = Hello.sni(chunk, 0, chunk.length);
                        else if ("http".equals(proto)) hostName = Hello.httpHost(chunk, 0, chunk.length);
                        rule = host.profile().matchTcp(srvPort, hostName);
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
                    wroteSomething = true;
                }

                if (clientDone && queued == 0 && !eofFromServer) {
                    try { Os.shutdown(fd, OsConstants.SHUT_WR); } catch (Exception ignored) { }
                    clientDone = false;
                }

                // 2) ответы сервера -> клиенту в туннель
                pollfd.events = (short) OsConstants.POLLIN;
                int pr = Os.poll(new StructPollfd[]{pollfd}, wroteSomething ? 0 : 200);
                if (pr > 0 && (pollfd.revents & (OsConstants.POLLIN | OsConstants.POLLHUP)) != 0) {
                    int n = Os.read(fd, rbuf, 0, Math.min(rbuf.length, MSS));
                    if (n <= 0) {
                        eofFromServer = true;
                        host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.FIN | Bits.ACK,
                                (int) Math.min(0xFFFF, peerWindow), null, 0, 0, 0));
                        break;
                    }
                    deliver(rbuf, 0, n);
                }

                if (!wroteSomething && System.currentTimeMillis() - lastActivity > IDLE_MS) {
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

    /** Отдаём клиенту данные сервера, нарезая сегментами по MSS. */
    private void deliver(byte[] buf, int off, int len) {
        int pos = off;
        int end = off + len;
        while (pos < end && !stopped) {
            int n = Math.min(MSS, end - pos);
            int window = (int) Math.max(1, Math.min(0xFFFF, peerWindow));
            host.toTun(Bits.buildTcp(tmpl, sndNxt, rcvNxt, Bits.ACK | Bits.PSH, window,
                    buf, pos, n, 0));
            sndNxt = (sndNxt + n) & 0xFFFFFFFFL;
            host.stats().bytesDown.addAndGet(n);
            pos += n;
        }
    }

    /** Сравниваем номера последовательности по модулю 2^32. */
    private static boolean seqBefore(long a, long b) {
        return (int) ((a - b) & 0xFFFFFFFFL) < 0;
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
