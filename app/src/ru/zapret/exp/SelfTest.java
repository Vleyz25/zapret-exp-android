package ru.zapret.exp;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Самопроверка: отвечает на вопрос «будет ли это работать в моей сети» без угадывания.
 *
 * Каждый сайт проверяется двумя способами подряд:
 *   1) «напрямую» — обычный TLS без десинхронизации;
 *   2) «с десинхом» — тот же самый ClientHello, но разрезанный по точкам из правила
 *      и с фейками, как делает твоя general (EXP).bat.
 *
 * Собственный трафик проверки НЕ идёт через туннель (наше приложение исключено из
 * маршрутов VpnService), то есть замеряется ровно то, что увидит инспекция провайдера.
 * Отсюда и вывод: если напрямую падает, а с десинхом проходит — стратегия работает.
 * Если падает и так, и так — дело не в приёме, а в том, что блокируется иначе.
 */
public final class SelfTest {

    public interface Sink {
        void line(String text);
    }

    private static final int CONNECT_MS = 6000;
    private static final int READ_MS = 6000;

    /** Хосты: два проблемных и один контрольный (его блокировать незачем). */
    private static final String[] TARGETS = {"youtube.com", "discord.com", "github.com"};

    private SelfTest() { }

    public static void run(final Profile profile, final Sink out) {
        out.line("=== самопроверка ===");
        out.line("туннель: " + (ZapretService.running ? "включён" : "выключен")
                + ", MTU " + Net.MTU + ", IPv6 вверх: " + (Net.IPV6_UP ? "есть" : "нет")
                + ", правил: " + profile.rules.size());
        out.line("проверка идёт напрямую (наше приложение исключено из туннеля) —"
                + " так видно, что делает инспекция провайдера");

        byte[] hello;
        try {
            hello = captureClientHello(TARGETS[0]);
            out.line("ClientHello получен от TLS-стека телефона: " + hello.length + " байт");
        } catch (Exception e) {
            out.line("НЕ ПОВТОРИМО: не удалось получить ClientHello: " + e);
            return;
        }

        List<String> verdicts = new ArrayList<String>();
        for (String host : TARGETS) {
            String direct = directTls(host);
            String desynced = desyncedTls(host, profile, out);
            verdicts.add(summarize(host, direct, desynced));
        }
        out.line("--- ИТОГ ---");
        for (String v : verdicts) out.line(v);
    }

    private static String summarize(String host, String direct, String desynced) {
        boolean okDirect = "ок".equals(direct);
        boolean okDesync = "ок".equals(desynced);
        if (okDirect && okDesync) return host + ": проходит и так, и с десинхом — блокировки нет";
        if (okDirect && !okDesync) return host + ": блокировки нет, но с десинхом хуже (" + desynced + ")";
        if (!okDirect && okDesync) return host + ": БЕЗ десинха блокируется, С десинхом проходит — стратегия работает";
        return host + ": не проходит ни так, ни так (" + direct + " / " + desynced + ") — блокировка не этого типа";
    }

    // ---------------------------------------------------------------- 1) напрямую

    private static String directTls(String host) {
        Socket s = null;
        SSLSocket tls = null;
        try {
            long t0 = System.currentTimeMillis();
            InetAddress addr = InetAddress.getByName(host);
            s = new Socket();
            s.connect(new InetSocketAddress(addr, 443), CONNECT_MS);
            SSLSocketFactory f = trustAllFactory();
            tls = (SSLSocket) f.createSocket(s, host, 443, true);
            tls.setSoTimeout(READ_MS);
            applySni(tls, host);
            tls.startHandshake();
            String proto = tls.getSession().getProtocol();
            long ms = System.currentTimeMillis() - t0;
            return "ok";
        } catch (Exception e) {
            return reason(e);
        } finally {
            close(tls);
            close(s);
        }
    }

    // ---------------------------------------------------------------- 2) с десинхом

    /**
     * Тот же ClientHello, но отправленный приёмами из правил: фрагменты + фейковое
     * соединение с малым TTL. Считываем первый ответ сервера: запись TLS (0x16 или 0x17)
     * значит, что инспекция пропустила разрезанный handshake.
     */
    private static String desyncedTls(String host, Profile profile, Sink out) {
        FileDescriptor fd = null;
        try {
            byte[] hello = captureClientHello(host);
            InetAddress addr = InetAddress.getByName(host);
            boolean v6 = addr.getAddress().length == 16;
            fd = Os.socket(v6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_STREAM, 0);
            FdOutputStream out2 = new FdOutputStream(fd);

            long t0 = System.currentTimeMillis();
            Os.connect(fd, addr, 443);

            Config.Rule rule = profile.matchTcp(443, host);
            boolean sample = false;
            if (rule == null) {
                rule = profile.desyncSample();               // github не в списках — берём образец
                sample = rule != null;
            }
            String proto = Hello.protocolOf(hello, 0, hello.length);
            out.line("  " + host + ": правило [" + (rule == null ? "нет" : rule.name) + "]"
                    + (sample ? " (образец: для этого хоста своего правила нет)" : "")
                    + (rule != null && rule.splitPos > 0
                            ? ", точки " + rule.splitPos + ":" + rule.splitRepeats
                                    + ":" + rule.splitSkip : "")
                    + (rule != null && rule.fake != null ? ", fake=" + rule.fakeName : ""));

            Desync.sendFirst(out2, v6, new InetSocketAddress(addr, 443),
                    hello, 0, hello.length, rule, proto, new Stats(), host);

            // читаем ответ: нам важна первая запись TLS
            StructPollfd pfd = new StructPollfd();
            pfd.fd = fd;
            pfd.events = (short) OsConstants.POLLIN;
            int pr = Os.poll(new StructPollfd[]{pfd}, READ_MS);
            if (pr <= 0) return "сервер молчит " + READ_MS + " мс (скорее всего вырезано)";
            byte[] buf = new byte[4096];
            int n = Os.read(fd, buf, 0, buf.length);
            if (n <= 0) return "сервер закрыл соединение";
            int type = buf[0] & 0xFF;
            long ms = System.currentTimeMillis() - t0;
            if (type == 0x16) {
                int hsType = n > 5 ? (buf[5] & 0xFF) : -1;
                return "ok" + (hsType == 2 ? " (ServerHello, " + ms + " мс)"
                        : " (handshake, тип " + hsType + ")");
            }
            if (type == 0x15) return "ок (пришёл TLS alert — handshake дошёл до сервера)";
            if (type == 0x17) return "ok (данные TLS сразу)";
            return "ок, но непонятный ответ: первый байт " + type;
        } catch (Throwable e) {
            return reason2(e);
        } finally {
            if (fd != null) {
                try { Os.close(fd); } catch (Exception ignored) { }
            }
        }
    }

    // ---------------------------------------------------------------- утилиты

    /**
     * Настоящий ClientHello для нужного имени: TLS-стек телефона отправляет его сам,
     * мы подсматриваем байты на локальном «сервере» и не продолжаем handshake.
     * Так проверка использует ровно те расширения и ту длину, что у реального соединения.
     */
    static byte[] captureClientHello(String host) throws Exception {
        final byte[][] holder = new byte[1][];
        ServerSocket ss = new ServerSocket(0, 4, InetAddress.getLoopbackAddress());
        final ServerSocket fss = ss;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Socket s = fss.accept();
                    byte[] buf = new byte[16384];
                    int total = 0, n;
                    long until = System.currentTimeMillis() + 3000;
                    while (total < buf.length && System.currentTimeMillis() < until) {
                        s.setSoTimeout(500);
                        try {
                            n = s.getInputStream().read(buf, total, buf.length - total);
                        } catch (Exception e) {
                            break;
                        }
                        if (n <= 0) break;
                        total += n;
                        // ClientHello обычно приходит одним куском
                        if (total > 40) {
                            int recLen = ((buf[3] & 0xFF) << 8) | (buf[4] & 0xFF);
                            if (buf[0] == 0x16 && total >= recLen + 5) break;
                        }
                    }
                    holder[0] = new byte[total];
                    System.arraycopy(buf, 0, holder[0], 0, total);
                    try { s.close(); } catch (Exception ignored) { }
                } catch (Exception ignored) { }
            }
        });
        t.setDaemon(true);
        t.start();

        SSLSocket c = null;
        try {
            c = (SSLSocket) trustAllFactory().createSocket();
            c.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), ss.getLocalPort()),
                    3000);
            applySni(c, host);
            c.startHandshake();
        } catch (Exception expected) {
            // сервер не TLS — handshake не продолжится, но ClientHello уже ушёл
        } finally {
            if (c != null) try { c.close(); } catch (Exception ignored) { }
            try { ss.close(); } catch (Exception ignored) { }
        }
        byte[] hello = holder[0];
        if (hello == null || hello.length < 40 || hello[0] != 0x16) {
            throw new IOException("ClientHello не пойман");
        }
        return hello;
    }

    private static void applySni(SSLSocket s, String host) {
        try {
            javax.net.ssl.SSLParameters p = s.getSSLParameters();
            List<javax.net.ssl.SNIServerName> names = new ArrayList<javax.net.ssl.SNIServerName>();
            names.add(new SNIHostName(host));
            p.setServerNames(names);
            s.setSSLParameters(p);
        } catch (Exception ignored) { }
    }

    /** Не проверяем сертификаты: нам важен факт handshake, а не его достоверность. */
    private static SSLSocketFactory trustAllFactory() throws Exception {
        TrustManager[] tm = new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) { }
            public void checkServerTrusted(X509Certificate[] c, String a) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new java.security.SecureRandom());
        return ctx.getSocketFactory();
    }

    /** Поток поверх файлового дескриптора: нужен, чтобы Desync работал и в самопроверке. */
    static final class FdOutputStream extends OutputStream {
        private final FileDescriptor fd;
        FdOutputStream(FileDescriptor fd) { this.fd = fd; }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                int done = 0;
                while (done < len) {
                    int w = Os.write(fd, b, off + done, len - done);
                    if (w <= 0) throw new IOException("запись закрыта");
                    done += w;
                }
            } catch (ErrnoException e) {
                throw new IOException(Os.strerror(e.errno), e);
            }
        }

        @Override
        public void write(int one) throws IOException {
            write(new byte[]{(byte) one}, 0, 1);
        }
    }

    private static void close(Socket s) {
        if (s != null) try { s.close(); } catch (Exception ignored) { }
    }

    private static String reason(Exception e) {
        String m = e.getMessage();
        if (m == null || m.isEmpty()) m = e.getClass().getSimpleName();
        return m;
    }

    private static String reason2(Throwable t) {
        if (t instanceof ErrnoException) {
            return Os.strerror(((ErrnoException) t).errno);
        }
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
