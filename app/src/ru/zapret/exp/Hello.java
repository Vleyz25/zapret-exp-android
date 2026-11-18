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
            // проходим question section
            int p = off + 12;
            while (p < off + len && (b[p] & 0xFF) != 0) p += 1 + (b[p] & 0xFF);
            p += 5;                                           // нуль + qtype + qclass
            int an = ((b[off + 8] & 0xFF) << 8) | (b[off + 9] & 0xFF);
            for (int i = 0; i < an && p + 12 <= off + len; i++) {
                // NAME (в том числе сжатые имена)
                while (p < off + len) {
                    int l = b[p] & 0xFF;
                    if (l == 0) { p++; break; }
                    if ((l & 0xC0) == 0xC0) { p += 2; break; }
                    p += 1 + l;
                }
                if (p + 10 > off + len) break;
                int type = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
                int rdLen = ((b[p + 8] & 0xFF) << 8) | (b[p + 9] & 0xFF);
                p += 10;
                if (p + rdLen > off + len) break;
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
