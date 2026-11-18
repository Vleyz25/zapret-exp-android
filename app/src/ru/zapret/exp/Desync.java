package ru.zapret.exp;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;

/**
 * Приёмы десинхронизации DPI на уровне сокета.
 *
 * Сопоставление с блоками general (EXP).bat:
 *   --dpi-desync-split-pos=1 + --repeats=N  -> несколько write() с TCP_NODELAY: ядро
 *                                              отдаёт те же байты другими сегментами
 *   --dpi-desync=fake (TCP)                 -> фейк уходит ОТДЕЛЬНЫМ соединением с малым
 *                                              TTL, чтобы не трогать последовательность
 *                                              настоящего потока (см. ниже про rootless)
 *   --dpi-desync=fake (QUIC/UDP)            -> дополнительные датаграммы с малым TTL:
 *                                              датаграммы независимые, поэтому это точный
 *                                              перенос приёма, без оговорок
 *   --dpi-desync-fooling=ts                 -> роль «не долететь до сервера» выполняет TTL
 *
 * Почему иначе, чем winws на ПК: Android без root не позволяет задать номер
 * последовательности, TCP Timestamp или вставить байты в чужой поток — этим на ПК
 * занимается WinDivert. Вставлять фейк в тот же сокет нельзя: сервер получил бы мусор
 * вместо начала ClientHello, и TLS бы развалился. Поэтому на TCP применяются только
 * сохраняющие поток приёмы (фрагментация), а фейки уходят отдельными потоками/датаграммами.
 */
public final class Desync {

    private static final String TAG = "Desync";

    // Номера опций, которых нет в android.system.OsConstants — берём как в Linux.
    private static final int IPPROTO_IP_LEVEL = 0;
    private static final int IPPROTO_IPV6_LEVEL = 41;
    private static final int IPPROTO_TCP_LEVEL = 6;
    private static final int IP_TTL = 1;
    private static final int IPV6_UNICAST_HOPS = 18;
    private static final int TCP_NODELAY = 1;
    private static final int TCP_MAXSEG = 2;

    /**
     * Очередь фейковых TCP-соединений. Её нельзя держать в самом потоке: фейк — это
     * отдельный handshake (SYN, ACK, отправка), то есть +1 RTT к каждой новой связи, и
     * именно поэтому «интернет тормозит» при включённом приложении. Один фоновый поток
     * делает это параллельно с настоящим соединением.
     */
    private static final ArrayDeque<Object[]> fakeQueue = new ArrayDeque<>();
    private static final Object fakeLock = new Object();
    private static final int FAKE_QUEUE_MAX = 16;

    private Desync() { }

    /**
     * Отправка первого запроса TCP-потока с десинхронизацией.
     * Байты оригинала уходят целиком и в том же порядке — поток не портится.
     *
     * @param out поток уже подключённого сокета «мы -> сервер»
     * @param fd  файловый дескриптор того же сокета (нужен для TCP_MAXSEG)
     */
    public static int sendFirst(OutputStream out, boolean v6,
                               InetSocketAddress server,
                               byte[] payload, int off, int len,
                               Config.Rule r, String appProto, Stats stats, String peer) {
        // TCP_NODELAY и размеры сегментов выставляет владелец сокета (TcpFlow):
        // публичный API Android не даёт взять файловый дескриптор у Socket, поэтому
        // ядро настраивается методами Socket, а не через setsockopt.
        try {
            if (r == null) {
                writeAll(out, payload, off, len);
                return len;
            }

            // 1) фейк: отдельное соединение с малым TTL, в фоне — он не должен
            //    задерживать настоящий handshake
            if (r.fake != null && r.fake.length > 0 && server != null) {
                scheduleFake(v6, server, r, stats, peer);
            }

            // 2) оригинал: фрагментируем по позициям из правила (тот же байтовый поток)
            int[] cuts = Splits.cuts(len, r.splitPos, r.splitRepeats, r.splitSkip, appProto);
            int prev = 0;
            for (int c : cuts) {
                if (c <= prev || c >= len) continue;
                writeAll(out, payload, off + prev, c - prev);
                prev = c;
            }
            if (len - prev > 0) writeAll(out, payload, off + prev, len - prev);

            if ("tls".equals(appProto)) stats.desyncTls.incrementAndGet();
            else if ("http".equals(appProto)) stats.desyncHttp.incrementAndGet();
            stats.log("десинк [" + r.name + "] " + appProto + " " + peer
                    + " фрагменты=" + java.util.Arrays.toString(cuts));
            return len;
        } catch (Exception e) {
            Log.w(TAG, "десинк не применён, отправляю целиком", e);
            stats.log("десинк [" + (r == null ? "?" : r.name) + "] не применён: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            try {
                writeAll(out, payload, off, len);
            } catch (Exception ignored) { }
            return len;
        }
    }

    private static void scheduleFake(boolean v6, InetSocketAddress server, Config.Rule r,
                                     Stats stats, String peer) {
        Object[] job = new Object[]{Boolean.valueOf(v6), server, r, stats, peer};
        synchronized (fakeLock) {
            if (fakeQueue.size() >= FAKE_QUEUE_MAX) fakeQueue.pollFirst();
            fakeQueue.add(job);
            if (fakeWorker == null) {
                fakeWorker = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        fakeLoop();
                    }
                }, "desync-fake");
                fakeWorker.setDaemon(true);
                fakeWorker.start();
            }
            fakeLock.notifyAll();
        }
    }

    private static Thread fakeWorker;

    private static void fakeLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            Object[] job;
            synchronized (fakeLock) {
                while ((job = fakeQueue.pollFirst()) == null) {
                    try {
                        fakeLock.wait();
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
            try {
                fakeConnection((Boolean) job[0], (InetSocketAddress) job[1],
                        (Config.Rule) job[2], (Stats) job[3], (String) job[4]);
            } catch (Exception e) {
                Log.d(TAG, "fake в фоне не удался: " + e);
            }
        }
    }

    /**
     * Фейковый ClientHello отдельным TCP-соединением с малым TTL.
     * Инспекция трафика его видит, а сервер — нет (пакеты умирают в пути).
     */
    public static void fakeConnection(boolean v6, InetSocketAddress server, Config.Rule r,
                                      Stats stats, String peer) {
        FileDescriptor fd = null;
        try {
            byte[] fake = Tls.withSni(r.fake, r.sni);
            fd = Os.socket(v6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_STREAM, 0);
            setHop(fd, v6, r.ttl);
            Os.connect(fd, server.getAddress(), server.getPort());
            for (int i = 0; i < r.repeat; i++) {
                writeAll(fd, fake, 0, fake.length);
            }
            stats.log("fake-соединение [" + r.name + "] " + r.fakeName + " x" + r.repeat
                    + " ttl=" + r.ttl + " -> " + peer);
        } catch (Exception e) {
            // Не ошибка приложения: фейк мог и не дойти до сервера — в этом весь смысл.
            Log.d(TAG, "fake-соединение не удалось: " + e);
        } finally {
            if (fd != null) {
                try { Os.close(fd); } catch (Exception ignored) { }
            }
        }
    }

    /**
     * Фейковые QUIC/UDP-датаграммы перед оригиналом. Отдельные датаграммы не влияют
     * на «поток», так что это прямой перенос --dpi-desync=fake для UDP из general (EXP).
     */
    public static void udpFakes(boolean v6, java.net.SocketAddress dst, byte[] data, int off, int len,
                                Config.Rule r, Stats stats, String peer) {
        FileDescriptor fd = null;
        try {
            fd = Os.socket(v6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_DGRAM, 0);
            setHop(fd, v6, r.ttl);
            byte[] fake = r.fake != null && r.fake.length > 0
                    ? r.fake
                    : java.util.Arrays.copyOfRange(data, off, off + len);
            for (int i = 0; i < r.repeat; i++) {
                Os.sendto(fd, fake, 0, fake.length, 0, dst);
            }
            stats.desyncQuic.incrementAndGet();
            stats.log("udp-fake [" + r.name + "] x" + r.repeat + " ttl=" + r.ttl + " -> " + peer);
        } catch (Exception e) {
            Log.d(TAG, "udp-fake пропущен: " + e);
        } finally {
            if (fd != null) {
                try { Os.close(fd); } catch (Exception ignored) { }
            }
        }
    }

    private static void setHop(FileDescriptor fd, boolean v6, int ttl) throws Exception {
        if (v6) Os.setsockoptInt(fd, IPPROTO_IPV6_LEVEL, IPV6_UNICAST_HOPS, ttl);
        else Os.setsockoptInt(fd, IPPROTO_IP_LEVEL, IP_TTL, ttl);
    }

    /** Пишем до конца (поток блокирующий). */
    public static void writeAll(OutputStream out, byte[] b, int off, int len) throws Exception {
        if (len <= 0) return;
        out.write(b, off, len);
        out.flush();
    }

    /** Пишем до конца (сокет блокирующий). */
    public static int writeAll(FileDescriptor fd, byte[] b, int off, int len) throws Exception {
        int done = 0;
        while (done < len) {
            int w = Os.write(fd, b, off + done, len - done);
            if (w <= 0) break;
            done += w;
        }
        return done;
    }

    /** Адрес назначения сокета из пакета туннеля. */
    public static InetSocketAddress serverAddress(byte[] addr, int port) {
        try {
            return new InetSocketAddress(InetAddress.getByAddress(addr), port);
        } catch (Exception e) {
            return null;
        }
    }
}
