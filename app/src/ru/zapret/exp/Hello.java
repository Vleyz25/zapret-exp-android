package ru.zapret.exp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Разбор прикладного заголовка первого запроса: TLS ClientHello (SNI) и HTTP (Host).
 * Нужен, чтобы применять десинхронизацию только к тем доменам, которые перечислены
 * в списках zapret с ПК — ровно как в winws --hostlist.
 */
public final class Hello {

    private Hello() { }

    /** Возвращает "tls"/"http"/"quic" или null, если не опознано. */
    public static String protocolOf(byte[] b, int off, int len) {
        if (len < 3) return null;
        int a = b[off] & 0xFF, bb = b[off + 1] & 0xFF;
        // TLS record: content type 22 (handshake), версия 0x03xx
        if (a == 0x16 && bb == 0x03) return "tls";
        // HTTP: GET/POST/HEAD/PUT/...
        if (len >= 5) {
            String head = new String(b, off, Math.min(len, 5), StandardCharsets.ISO_8859_1);
            if (head.equals("GET /") || head.equals("POST ") || head.equals("PUT /")
                    || head.equals("HEAD ") || head.equals("CONNE") || head.equals("OPTIO")) {
                return "http";
            }
        }
        return null;
    }

    /** SNI из ClientHello. null — если не нашли. */
    public static String sni(byte[] b, int off, int len) {
        if (len < 52) return null;
        if ((b[off] & 0xFF) != 0x16) return null;             // handshake record
        int recLen = ((b[off + 3] & 0xFF) << 8) | (b[off + 4] & 0xFF);
        int h = off + 5;
        if (h + 4 > off + len) return null;
        if ((b[h] & 0xFF) != 0x01) return null;               // ClientHello
        int hsLen = ((b[h + 1] & 0xFF) << 16) | ((b[h + 2] & 0xFF) << 8) | (b[h + 3] & 0xFF);
        int p = h + 4;                                        // legacy_version
        int end = Math.min(h + 4 + hsLen, off + len);
        if (p + 2 > end) return null;
        p += 2;                                               // version
        if (p + 32 > end) return null;
        p += 32;                                              // random
        int sidLen = b[p] & 0xFF;
        p += 1 + sidLen;
        if (p + 2 > end) return null;
        int csLen = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
        p += 2 + csLen;
        if (p + 1 > end) return null;
        int compLen = b[p] & 0xFF;
        p += 1 + compLen;
        if (p + 2 > end) return null;
        int extTotal = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
        p += 2;
        int extEnd = Math.min(p + extTotal, end);
        while (p + 4 <= extEnd) {
            int type = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
            int size = ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
            p += 4;
            if (p + size > extEnd) break;
            if (type == 0) {                                  // server_name
                int sn = p;
                if (sn + 5 <= p + size) {
                    int listLen = ((b[sn] & 0xFF) << 8) | (b[sn + 1] & 0xFF);
                    int nameLen = ((b[sn + 3] & 0xFF) << 8) | (b[sn + 4] & 0xFF);
                    int nameOff = sn + 5;
                    if (nameOff + nameLen <= sn + 2 + listLen && nameOff + nameLen <= extEnd) {
                        return new String(b, nameOff, nameLen, StandardCharsets.US_ASCII).toLowerCase();
                    }
                }
            }
            p += size;
        }
        return null;
    }

    /** Host из HTTP-запроса (заголовок Host:). */
    public static String httpHost(byte[] b, int off, int len) {
        int end = off + len;
        int limit = Math.min(end, off + 4096);
        String s = new String(b, off, limit - off, StandardCharsets.ISO_8859_1);
        int line = 0;
        while (line < s.length()) {
            int nl = s.indexOf('\n', line);
            if (nl < 0) nl = s.length();
            String l = s.substring(line, nl).trim();
            line = nl + 1;
            if (l.isEmpty()) break;
            if (l.regionMatches(true, 0, "Host:", 0, 5)) {
                String v = l.substring(5).trim();
                int sp = v.indexOf(' ');
                if (sp > 0) v = v.substring(0, sp);
                int colon = v.lastIndexOf(':');
                if (colon > 0 && v.indexOf(']') < 0) v = v.substring(0, colon);
                return v.toLowerCase();
            }
        }
        return null;
    }


    /** Пропустить DNS-имя, включая сжатые имена (указатель 0xC0 заверщает имя). */
    private static int skipName(byte[] b, int p, int end) {
        while (p < end) {
            int l = b[p] & 0xFF;
            if (l == 0) return p + 1;
            if ((l & 0xC0) == 0xC0) return p + 2;
            p += 1 + l;
        }
        return -1;
    }

    /**
     * Убрать из DNS-ответа записи AAAA. Нужно, когда у оператора нет IPv6-канала:
     * туннель всё равно объявляет маршрут ::/0, приложение видит «IPv6 есть» и
     * подключается к AAAA-адресу, которого в реальности нет — отсюда «нет связи»
     * там, где на ПК всё работает. Без IPv6 вверх отдаём только A-записи.
     * null — если убирать нечего или ответ не разбирается (тогда не трогаем).
     */
    public static byte[] dnsStripAaaa(byte[] b, int off, int len) {
        try {
            if (len - off < 12) return null;
            if ((b[off + 2] & 0x80) == 0) return null;              // не ответ
            int end = off + len;
            int p = off + 12;
            int qd = u16(b, off + 4);
            for (int i = 0; i < qd; i++) {
                p = skipName(b, p, end);
                if (p < 0 || p + 4 > end) return null;
                p += 4;
            }
            int an = u16(b, off + 6);
            int ansStart = p;
            java.io.ByteArrayOutputStream kept = new java.io.ByteArrayOutputStream(len);
            int keptCount = 0;
            boolean changed = false;
            for (int i = 0; i < an; i++) {
                int rrStart = p;
                p = skipName(b, p, end);
                if (p < 0 || p + 10 > end) return null;
                int type = u16(b, p);
                int rdlen = u16(b, p + 8);
                p += 10;
                if (p + rdlen > end) return null;
                int rrEnd = p + rdlen;
                if (type == 28) {
                    changed = true;                                  // AAAA выбрасываем
                } else {
                    kept.write(b, rrStart, rrEnd - rrStart);
                    keptCount++;
                }
                p = rrEnd;
            }
            if (!changed) return null;
            byte[] keepBytes = kept.toByteArray();
            int rest = end - p;                                      // authority + additional
            byte[] out = new byte[ansStart - off + keepBytes.length + rest];
            System.arraycopy(b, off, out, 0, ansStart - off);        // заголовок + вопрос
            System.arraycopy(keepBytes, 0, out, ansStart - off, keepBytes.length);
            System.arraycopy(b, p, out, ansStart - off + keepBytes.length, rest);
            out[6] = (byte) (keptCount >> 8);                        // новый ANCOUNT
            out[7] = (byte) keptCount;
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /** Короткое описание ответов для журнала: «A x2, AAAA x1». */
    public static String dnsAnswerKinds(byte[] b, int off, int len) {
        try {
            if ((b[off + 2] & 0x80) == 0) return null;
            int end = off + len;
            int p = off + 12;
            int qd = u16(b, off + 4);
            for (int i = 0; i < qd; i++) {
                p = skipName(b, p, end);
                if (p < 0 || p + 4 > end) return null;
                p += 4;
            }
            int an = u16(b, off + 6);
            int a = 0, aaaa = 0, other = 0;
            for (int i = 0; i < an; i++) {
                p = skipName(b, p, end);
                if (p < 0 || p + 10 > end) break;
                int type = u16(b, p);
                int rdlen = u16(b, p + 8);
                p += 10;
                if (p + rdlen > end) break;
                if (type == 1) a++;
                else if (type == 28) aaaa++;
                else other++;
                p += rdlen;
            }
            StringBuilder sb = new StringBuilder();
            if (a > 0) sb.append("A x").append(a);
            if (aaaa > 0) sb.append(sb.length() > 0 ? ", AAAA x" : "AAAA x").append(aaaa);
            if (other > 0) sb.append(sb.length() > 0 ? ", прочих " : "прочих ").append(other);
            if ((b[off + 3] & 0x0F) != 0) sb.append(", rcode=").append(b[off + 3] & 0x0F);
            return sb.length() == 0 ? null : sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    /** Имя домена из DNS-запроса (для сопоставления IP <-> домен). */
    public static String dnsQueryName(byte[] b, int off, int len) {
        try {
            int p = off + 12;
            StringBuilder sb = new StringBuilder();
            int guard = 0;
            while (p < off + len) {
                int l = b[p] & 0xFF;
                if (l == 0) break;
                if (l > 63 || guard++ > 128) return null;
                p++;
                if (p + l > off + len) return null;
                if (sb.length() > 0) sb.append('.');
                sb.append(new String(b, p, l, StandardCharsets.US_ASCII));
                p += l;
            }
            return sb.length() == 0 ? null : sb.toString().toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Вытаскивает адреса A/AAAA из DNS-ответа: нужно для правил по QUIC, где SNI
     * недоступен (Initial зашифрован) — zapret на ПК в таких случаях опирается на
     * ipset, мы опираемся на сопоставление «домен -> IP» из собственных ответов DNS.
     */
    /**
     * Ключ DNS-вопроса: имя + тип + класс. ID в ключ не входит, потому что он у каждого
     * запроса свой — при ответе из кэша мы подставляем ID обратно.
     */
    public static String dnsQuestionKey(byte[] b, int off, int len) {
        if (len - off < 12) return null;
        int i = off + 12;
        while (i < off + len) {
            int l = b[i] & 0xFF;
            if (l == 0) { i++; break; }
            if ((l & 0xC0) != 0) return null;         // сжатие имени в запросе не встречается
            i += l + 1;
        }
        if (i + 4 > off + len) return null;
        int type = ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
        int cls = ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
        String name = dnsQueryName(b, off, len);
        if (name == null) return null;
        return name.toLowerCase() + '|' + type + '|' + cls;
    }

    public static List<byte[]> dnsAnswerAddresses(byte[] b, int off, int len) {
        List<byte[]> addrs = new ArrayList<>();
        try {
            int end = off + len;
            if (len < 12 || (b[off + 2] & 0x80) == 0) return addrs;      // не ответ
            int p = off + 12;
            int qd = u16(b, off + 4);
            for (int i = 0; i < qd; i++) {
                p = skipName(b, p, end);
                if (p < 0 || p + 4 > end) return addrs;
                p += 4;
            }
            // ANCOUNT — смещение 6. Раньше здесь читалось смещение 8 (NSCOUNT), из-за
            // чего карта «домен -> IP» для QUIC-правил не наполнялась никогда.
            int an = u16(b, off + 6);
            for (int i = 0; i < an; i++) {
                p = skipName(b, p, end);
                if (p < 0 || p + 10 > end) break;
                int type = u16(b, p);
                int rdLen = u16(b, p + 8);
                p += 10;
                if (p + rdLen > end) break;
                if (type == 1 && rdLen == 4) addrs.add(sub(b, p, 4));
                else if (type == 28 && rdLen == 16) addrs.add(sub(b, p, 16));
                p += rdLen;
            }
        } catch (Exception e) {
            /* DNS-пакет необычный — просто не запоминаем соответствия */
        }
        return addrs;
    }

    private static byte[] sub(byte[] b, int off, int len) {
        byte[] r = new byte[len];
        System.arraycopy(b, off, r, 0, len);
        return r;
    }
}
