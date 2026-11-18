package ru.zapret.exp;

/**
 * Настройки сети туннеля в одном месте и без зависимостей от Android — тогда ядро
 * (Bits, Hello, Splits, Window, TcpFlow, Desync) можно прогонять на обычной JVM,
 * в том числе против настоящих TLS-серверов.
 */
public final class Net {

    /** MTU туннеля; подбирается под реальный линк в ZapretService.discoverMtu(). */
    public static volatile int MTU = 1400;

    /** Есть ли у оператора IPv6-канал (global-адрес на активном линке). */
    public static volatile boolean IPV6_UP = true;

    /** Размер сегмента для данного семейства при текущем MTU. */
    public static int mss(boolean v6) {
        int m = MTU - (v6 ? 60 : 40);
        return m < 536 ? 536 : m;
    }

    private Net() { }
}
