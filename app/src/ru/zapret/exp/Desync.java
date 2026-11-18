package ru.zapret.exp;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;

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
 *                                              датаграммы независимы, поэтому это точный
 *                                              перенос приёма, без оговорок
 *   --dpi-desync-fooling=ts                 -> роль «не долететь до сервера» выполняет TTL
 *
 * Почему иначе, чем winws на ПК: Android без root не позволяет задать номер
 * последовательности, TCP Timestamp или вставить байты в чужой поток — этим на ПК
 * занимается WinDivert. Вставлять фейк в тот же сокет нельзя: сервер получил бы мусор
 * вместо начала ClientHello и TLS бы развалился. Поэтому на TCP применяются только
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

    private Desync() { }

    /**
     * Отправка первого запроса TCP-потока с десинхронизацией.
     * Байты оригинала уходят целиком и в том же порядке — поток не портится.
     */
    public static int sendFirst(FileDescriptor fd, boolean v6, InetSocketAddress server,
                               byte[] payload, int off, int len,
                               Config.Rule r, String appProto, Stats stats, String peer) {
        try {
            Os.setsockoptInt(fd, IPPROTO_TCP_LEVEL, TCP_NODELAY, 1);
        } catch (ErrnoException e) {
            Log.d(TAG, "TCP_NODELAY: " + e);
        }
        // Дополнительный рычаг: уменьшить MSS, чтобы ClientHello шёл ещё более
        // мелкими сегментами. Байты не меняются, поток остаётся валидным.
        if (r != null && r.mss >= 88) {
            try {
                Os.setsockoptInt(fd, IPPROTO_TCP_LEVEL, TCP_MAXSEG, r.mss);
                stats.desyncTls.incrementAndGet();
            } catch (ErrnoException e) {
                Log.d(TAG, "TCP_MAXSEG: " + e);
            }
        }

        try {
            if (r == null) {
                writeAll(fd, payload, off, len);
                return len;
            }

            // 1) фейк: отдельное соединение с малым TTL (не трогает наш поток)
            if (r.fake != null && r.fake.length > 0 && server != null) {
                fakeConnection(v6, server, r, stats, peer);
            }

            // 2) оригинал: фрагментируем по позициям из правила (тот же байтовый поток)
            int[] cuts = Splits.cuts(len, r.splitPos, r.splitRepeats, r.splitSkip, appProto);
            int prev = 0;
            for (int c : cuts) {
                if (c <= prev || c >= len) continue;
                writeAll(fd, payload, off + prev, c - prev);
                prev = c;
            }
            writeAll(fd, payload, off + prev, len - prev);

            if ("tls".equals(appProto)) stats.desyncTls.incrementAndGet();
            else if ("http".equals(appProto)) stats.desyncHttp.incrementAndGet();
            stats.log("десинк [" + r.name + "] " + appProto + " " + peer
                    + " фрагменты=" + java.util.Arrays.toString(cuts));
            return len;
        } catch (Exception e) {
            Log.w(TAG, "десинк не применён, отправляю целиком", e);
            try {
                writeAll(fd, payload, off, len);
            } catch (Exception ignored) { }
            return len;
        }
    }

    /**
     * Фейковый ClientHello отдельным TCP-соединением с малым TTL.
     * Инспекция трафика видит его, а сервер — нет (пакеты умирают в пути).
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
            Log.d(TAG, "fake-соединение не удалось: " + e);
        } finally {
            if (fd != null) {
                try { Os.close(fd); } catch (Exception ignored) { }
            }
        }
    }

    /**
     * фейковые QUIC/UDP-датаграммы перед оригиналом. Отдельные датаграммы не влияют
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
