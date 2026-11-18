package ru.zapret.exp;

import java.util.TreeSet;

/**
 * Точки разбиения исходящего запроса. Чистая логика без Android-API: её можно
 * проверить на обычной JVM (см. tests/CoreTest.java).
 *
 * соответствие general (EXP).bat:
 *   --dpi-desync-split-pos=1 --dpi-desync-repeats=4   -> split=1:4:1
 *   --dpi-desync-split-pos=1 --dpi-desync-repeats=8   -> split=1:8:1
 * плюс разделение заголовка TLS-записи (первые 5 байт), аналог --tlsrec 1.
 */
public final class Splits {

    private Splits() { }

    public static int[] cuts(int len, int pos, int repeats, int skip, String appProto) {
        TreeSet<Integer> set = new TreeSet<>();
        if (pos > 0) {
            int step = Math.max(1, skip + 1);
            int p = pos;
            int n = repeats <= 0 ? 1 : repeats;
            for (int i = 0; i < n && p < len; i++) {
                set.add(p);
                p += step;
            }
        }
        if ("tls".equals(appProto) && len > 6) set.add(5);
        if (set.isEmpty()) {
            if (len > 1) set.add(1);
        }
        int[] out = new int[set.size()];
        int i = 0;
        for (Integer v : set) out[i++] = v;
        return out;
    }

    /** Сколько байт уйдёт в k-м сегменте при заданных точках разбиения. */
    public static int segmentSize(int len, int[] cuts, int k) {
        int start = k == 0 ? 0 : cuts[k - 1];
        int end = k < cuts.length ? cuts[k] : len;
        return end - start;
    }

    public static int segments(int len, int[] cuts) {
        return cuts.length + (cuts.length > 0 && cuts[cuts.length - 1] < len ? 1 : (cuts.length == 0 ? 1 : 0));
    }
}
