package ru.zapret.exp;

/**
 * Управление окном TCP-стороны туннеля. Чистая арифметика, вынесенная из
 * TcpFlow, чтобы её можно было проверить на обычной JVM (в том числе переходы
 * через 32-битное число).
 *
 * Мы сами являемся «сервером» для приложений телефона, поэтому обязаны уважать
 * объявленное ими окно: иначе данные уйдут сверх window, клиент их отбросит,
 * а повторной передачи у нас нет — получится вечная пауза вместо видео.
 * MSS-опция в SYN-ACK объявляется без window scaling, значит окно клиента
 * не масштабировано и его поле можно использовать как есть (до 65535 байт).
 */
public final class Window {

    private Window() { }

    /** Сколько байт наших данных ещё не подтверждено (по модулю 2^32). */
    public static long inflight(long sndNxt, long peerAcked) {
        return (sndNxt - peerAcked) & 0xFFFFFFFFL;
    }

    /**
     * Сколько байт можно отправить сейчас. window передаётся уже масштабированным:
     * сырое поле окна из заголовка умножается на 1&lt;&lt;scale (RFC 7323), иначе потолок
     * — 65535 байт на круг, около 1 МБ/с на мобильном RTT.
     */
    public static long allowed(long sndNxt, long peerAcked, long window) {
        long w = window < 0 ? 0 : window;
        long used = inflight(sndNxt, peerAcked);
        long free = w - used;
        return free < 0 ? 0 : free;
    }

    /** Сравнение номеров последовательности как кольцевых 32-битных (RFC 1982). */
    public static boolean serialAfter(long a, long b) {
        long d = (a - b) & 0xFFFFFFFFL;
        return d != 0 && d < 0x80000000L;
    }

    /** Обновить «подтверждено» с учётом обёртки: только вперёд. */
    public static long advanceAcked(long peerAcked, long newAck) {
        return serialAfter(newAck, peerAcked) ? newAck : peerAcked;
    }
}
