package ru.zapret.exp;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Разбор и сборка IP/TCP/UDP заголовков вручную.
 *
 * Почему вручную: Android без root не даёт перехватывать пакеты на сетевом уровне
 * (на ПК это делает winws.exe через WinDivert), поэтому приложение поднимает туннель
 * VpnService и работает с IP-пакетами как с байтами. Всё, что нужно для десинхронизации
 * DPI (фрагментация, фейки с малым TTL, QUIC-фейки), строится здесь и на сокетах через
 * android.system.Os.
 */
public final class Bits {

    public static final int V4 = 4;
    public static final int V6 = 6;

    public static final int IPPROTO_TCP = 6;
    public static final int IPPROTO_UDP = 17;

    // TCP-флаги
    public static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    /** Разобранный пакет. */
    public static final class Pkt {
        public byte[] buf;      // исходный буфер
        public int total;       // длина всего пакета
        public int family;      // V4 / V6
        public int proto;       // IPPROTO_TCP / IPPROTO_UDP / другой
        public byte[] src;      // 4 или 16 байт
        public byte[] dst;
        public int sport, dport;
        public int l4Off;       // начало TCP/UDP-заголовка
        public int dataOff;     // начало полезной нагрузки
        public int dataLen;     // длина полезной нагрузки
        // только для TCP
        public long seq, ackNum;
        public int flags, window, headerLen;
    }

    private Bits() { }

    static int u8(byte[] b, int i) { return b[i] & 0xFF; }
    static int u16(byte[] b, int i) { return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); }
    static long u32(byte[] b, int i) {
        return ((long) (b[i] & 0xFF) << 24) | ((long) (b[i + 1] & 0xFF) << 16)
                | ((long) (b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
    }
    static void put16(byte[] b, int i, int v) {
        b[i] = (byte) (v >> 8);
        b[i + 1] = (byte) v;
    }
    static void put32(byte[] b, int i, long v) {
        b[i] = (byte) (v >> 24);
        b[i + 1] = (byte) (v >> 16);
        b[i + 2] = (byte) (v >> 8);
        b[i + 3] = (byte) v;
    }

    /** Разбор пакета из буфера. null — если пакет непонятный или обрезанный. */
    public static Pkt parse(byte[] buf, int len) {
        if (len < 20) return null;
        Pkt p = new Pkt();
        p.buf = buf;
        p.total = len;
        int ver = (buf[0] & 0xFF) >> 4;
        int l4Start, l4End;

        if (ver == 4) {
            int ihl = (buf[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl) return null;
            if ((u16(buf, 6) & 0x3FFF) != 0) return null;       // фрагменты не разбираем
            int total = u16(buf, 2);
            if (total < 20 || total > len) total = len;
            p.family = V4;
            p.proto = u8(buf, 9);
            p.src = slice(buf, 12, 4);
            p.dst = slice(buf, 16, 4);
            l4Start = ihl;
            l4End = total;
        } else if (ver == 6) {
            if (len < 40) return null;
            int payload = u16(buf, 4);
            int next = u8(buf, 6);
            int end = 40 + Math.min(payload, len - 40);
            int off = 40;
            while (off + 8 <= end && (next == 0 || next == 43 || next == 60)) {
                if (next == 44) return null;                    // fragment header
                int nh = u8(buf, off);
                int hl = (next == 43) ? (u8(buf, off + 1) + 1) * 8 : 8;
                next = nh;
                off += hl;
            }
            p.family = V6;
            p.proto = next;
            p.src = slice(buf, 8, 16);
            p.dst = slice(buf, 24, 16);
            l4Start = off;
            l4End = end;
        } else {
            return null;
        }

        if (l4End < l4Start) l4End = l4Start;
        p.l4Off = l4Start;
        p.dataOff = l4Start;
        p.dataLen = l4End - l4Start;

        if (p.proto == IPPROTO_TCP) {
            if (l4Start + 20 > l4End) return null;
            p.sport = u16(buf, l4Start);
            p.dport = u16(buf, l4Start + 2);
            p.seq = u32(buf, l4Start + 4);
            p.ackNum = u32(buf, l4Start + 8);
            p.headerLen = ((buf[l4Start + 12] & 0xFF) >> 4) * 4;
            if (p.headerLen < 20 || l4Start + p.headerLen > l4End) return null;
            p.flags = u8(buf, l4Start + 13);
            p.window = u16(buf, l4Start + 14);
            p.dataOff = l4Start + p.headerLen;
            p.dataLen = Math.max(0, l4End - p.dataOff);
        } else if (p.proto == IPPROTO_UDP) {
            if (l4Start + 8 > l4End) return null;
            p.sport = u16(buf, l4Start);
            p.dport = u16(buf, l4Start + 2);
            int ul = u16(buf, l4Start + 4);
            if (ul < 8) ul = l4End - l4Start;
            p.dataOff = l4Start + 8;
            p.dataLen = Math.max(0, Math.min(l4Start + ul, l4End) - p.dataOff);
        }
        return p;
    }

    /** Контрольная сумма RFC 1071 поверх seed. */
    public static int checksum(byte[] buf, int off, int len, long seed) {
        long sum = seed;
        int i = off, end = off + len;
        while (i + 1 < end) {
            sum += ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) sum += ((buf[i] & 0xFF) << 8);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    /** Псевдо-заголовок для TCP/UDP-контрольной суммы. */
    private static long pseudoSeed(byte[] src, byte[] dst, int proto, int l4Len) {
        long sum = 0;
        if (src.length == 4) {
            for (int i = 0; i < 4; i += 2) sum += ((src[i] & 0xFF) << 8) | (src[i + 1] & 0xFF);
            for (int i = 0; i < 4; i += 2) sum += ((dst[i] & 0xFF) << 8) | (dst[i + 1] & 0xFF);
            sum += proto + l4Len;
        } else {
            for (int i = 0; i < 16; i += 2) {
                sum += ((src[i] & 0xFF) << 8) | (src[i + 1] & 0xFF);
                sum += ((dst[i] & 0xFF) << 8) | (dst[i + 1] & 0xFF);
            }
            sum += l4Len + proto;
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return sum;
    }

    public static byte[] slice(byte[] b, int off, int len) {
        byte[] r = new byte[len];
        System.arraycopy(b, off, r, 0, len);
        return r;
    }

    public static int ipHeaderLen(int family) { return family == V4 ? 20 : 40; }
    static int ipSrcOff(int family) { return family == V4 ? 12 : 8; }
    static int ipDstOff(int family) { return family == V4 ? 16 : 24; }

    /**
     * Сборка IP+TCP пакета-ответа в туннель: адреса и порты разворачиваются,
     * то есть для приложения мы выглядим как тот сервер, к которому оно подключилось.
     *
     * @param in     пакет клиента, на который отвечаем
     * @param seq    наша последовательность
     * @param ack    что подтверждаем
     * @param flags  TCP-флаги
     * @param window объявляемое окно
     * @param payload данные или null
     * @param mss    если > 0 — добавляется опция MSS (нужно в SYN-ACK)
     */
    public static byte[] buildTcp(Pkt in, long seq, long ack, int flags, int window,
                                  byte[] payload, int pOff, int pLen, int mss) {
        int ihl = ipHeaderLen(in.family);
        int tcpLen = mss > 0 ? 24 : 20;
        if (payload == null) pLen = 0;
        int total = ihl + tcpLen + pLen;
        byte[] b = new byte[total];

        if (in.family == V4) {
            b[0] = 0x45;
            put16(b, 2, total);
            put16(b, 6, 0x4000);          // DF
            b[8] = 64;                    // TTL
            b[9] = (byte) IPPROTO_TCP;
            System.arraycopy(in.dst, 0, b, 12, 4);   // «сервер»
            System.arraycopy(in.src, 0, b, 16, 4);   // клиент в туннеле
            put16(b, 10, checksum(b, 0, 20, 0));
        } else {
            b[0] = 0x60;
            put16(b, 4, tcpLen + pLen);
            b[6] = (byte) IPPROTO_TCP;
            b[7] = 64;                    // hop limit
            System.arraycopy(in.dst, 0, b, 8, 16);
            System.arraycopy(in.src, 0, b, 24, 16);
        }

        int t = ihl;
        put16(b, t, in.dport);
        put16(b, t + 2, in.sport);
        put32(b, t + 4, seq);
        put32(b, t + 8, ack);
        b[t + 12] = (byte) ((tcpLen / 4) << 4);
        b[t + 13] = (byte) flags;
        put16(b, t + 14, window & 0xFFFF);
        if (mss > 0) {
            b[t + 20] = 2;
            b[t + 21] = 4;
            put16(b, t + 22, mss);
        }
        if (pLen > 0) System.arraycopy(payload, pOff, b, t + tcpLen, pLen);

        int l4Len = tcpLen + pLen;
        byte[] myAddr = slice(b, ipSrcOff(in.family), in.src.length);
        byte[] peerAddr = slice(b, ipDstOff(in.family), in.src.length);
        put16(b, t + 16, nonZero(checksum(b, t, l4Len, pseudoSeed(myAddr, peerAddr, IPPROTO_TCP, l4Len))));
        return b;
    }

    /** Сборка IP+UDP-пакета-ответа в туннель (DNS и UDP-релей). */
    public static byte[] buildUdp(Pkt in, byte[] payload, int pOff, int pLen) {
        int ihl = ipHeaderLen(in.family);
        int total = ihl + 8 + pLen;
        byte[] b = new byte[total];

        if (in.family == V4) {
            b[0] = 0x45;
            put16(b, 2, total);
            put16(b, 6, 0x4000);
            b[8] = 64;
            b[9] = (byte) IPPROTO_UDP;
            System.arraycopy(in.dst, 0, b, 12, 4);
            System.arraycopy(in.src, 0, b, 16, 4);
            put16(b, 10, checksum(b, 0, 20, 0));
        } else {
            b[0] = 0x60;
            put16(b, 4, 8 + pLen);
            b[6] = (byte) IPPROTO_UDP;
            b[7] = 64;
            System.arraycopy(in.dst, 0, b, 8, 16);
            System.arraycopy(in.src, 0, b, 24, 16);
        }

        int u = ihl;
        put16(b, u, in.dport);
        put16(b, u + 2, in.sport);
        put16(b, u + 4, 8 + pLen);
        if (pLen > 0) System.arraycopy(payload, pOff, b, u + 8, pLen);

        byte[] myAddr = slice(b, ipSrcOff(in.family), in.src.length);
        byte[] peerAddr = slice(b, ipDstOff(in.family), in.src.length);
        put16(b, u + 6, nonZero(checksum(b, u, 8 + pLen, pseudoSeed(myAddr, peerAddr, IPPROTO_UDP, 8 + pLen))));
        return b;
    }

    private static int nonZero(int sum) { return sum == 0 ? 0xFFFF : sum; }

    public static String addrToString(byte[] a) {
        StringBuilder sb = new StringBuilder();
        if (a.length == 4) {
            for (int i = 0; i < 4; i++) {
                if (i > 0) sb.append('.');
                sb.append(a[i] & 0xFF);
            }
        } else {
            for (int i = 0; i < 16; i += 2) {
                if (i > 0) sb.append(':');
                sb.append(Integer.toHexString(((a[i] & 0xFF) << 8) | (a[i + 1] & 0xFF)));
            }
        }
        return sb.toString();
    }

    public static InetAddress toAddress(byte[] a) throws UnknownHostException {
        return InetAddress.getByAddress(a);
    }

    public static boolean sameAddr(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    /** Ключ потока: протокол + адреса + порты (в обе стороны — один и тот же ключ). */
    public static String flowKey(int proto, byte[] a, int pa, byte[] b, int pb) {
        return proto + ":" + addrToString(a) + ":" + pa + ":" + addrToString(b) + ":" + pb;
    }

    public static String human(long bytes) {
        if (bytes < 1024) return bytes + " Б";
        if (bytes < 1024 * 1024) return String.format("%.1f КБ", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f МБ", bytes / (1024.0 * 1024));
        return String.format("%.2f ГБ", bytes / (1024.0 * 1024 * 1024));
    }
}
