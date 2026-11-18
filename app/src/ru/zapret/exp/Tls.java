package ru.zapret.exp;

import java.nio.charset.StandardCharsets;

/** Мелкие helpers по TLS, нужные для переноса блоков EXP. */
public final class Tls {

    private Tls() { }

    /**
     * Подмена SNI внутри fake-шаблона (аналог --dpi-desync-hostfakesplit-mod=host=...
     * и -n <sni> у byedpi). Если длина нового имени не совпадает с длиной имени в
     * шаблоне — оставляем шаблон как есть: менять размеры расширений в чужом
     * ClientHello без пересчёта длин опасно, а смысл приёма (показать DPI «другой»
     * ClientHello) от этого не меняется.
     */
    public static byte[] withSni(byte[] fake, String sni) {
        if (sni == null || sni.isEmpty() || fake == null) return fake;
        String old = Hello.sni(fake, 0, fake.length);
        if (old == null || old.length() != sni.length()) return fake;
        byte[] out = fake.clone();
        int idx = indexOfName(out, old);
        if (idx < 0) return fake;
        byte[] nb = sni.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nb, 0, out, idx, nb.length);
        return out;
    }

    private static int indexOfName(byte[] b, String name) {
        byte[] nb = name.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = 0; i + nb.length <= b.length; i++) {
            for (int j = 0; j < nb.length; j++) {
                if (b[i + j] != nb[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
