package ru.zapret.exp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Стенд: настоящий TcpFlow между синтетическим TCP-клиентом (мы играем приложение
 * телефона, которое говорит с туннелем) и настоящим сервером.
 *
 * Проверяет то, что невозможно проверить разбором пакетов по отдельности:
 *   - рукипожатие SYN / SYN-ACK / ACK с корректными номерами и опциями;
 *   - что разрыв соединения и обрывы не превращаются в RST там, где всё хорошо;
 *   - что 300 КБ в обе стороны приходят байт в байт и по порядку (окна, pump, очереди);
 *   - что фрагментированный ClientHello (десинхронизация) не ломает настоящий TLS;
 *   - что все пакеты, которые мы отправляем «клиенту», имеют верные контрольные суммы.
 *
 * Запуск: bash run_relay_test.sh          (без root, без телефона; тест B нужен интернет)
 */
public class RelayTest {

    static int passed = 0, failed = 0;
    static final List<String> fails = new ArrayList<String>();

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
            System.out.println("  ok   " + name);
        } else {
            failed++;
            fails.add(name + "  " + detail);
            System.out.println("  FAIL " + name + "  " + detail);
        }
    }

    static void eq(String name, Object actual, Object expected) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        check(name, ok, "ожидалось=" + expected + " получилось=" + actual);
    }

    // ---------------------------------------------------------------- общий каркас

    /** Пакеты, которые TcpFlow шлёт «клиенту». */
    static class Tunnel {
        final ConcurrentLinkedQueue<byte[]> toClient = new ConcurrentLinkedQueue<byte[]>();
        final Object signal = new Object();
        volatile Profile profile;
        final Stats stats = new Stats();
        volatile TcpFlow flow;
        final List<String> badPackets = new ArrayList<String>();

        TcpFlow.Host host() {
            return new TcpFlow.Host() {
                @Override
                public void protectFd(java.io.FileDescriptor fd) { }

                @Override
                public void toTun(byte[] packet) {
                    String err = Bits.verify(packet, packet.length);
                    if (err != null) {
                        synchronized (badPackets) {
                            if (badPackets.size() < 5) badPackets.add(err);
                        }
                    }
                    toClient.add(packet);
                    synchronized (signal) { signal.notifyAll(); }
                }

                @Override
                public Profile profile() { return profile; }

                @Override
                public Stats stats() { return stats; }
            };
        }

        byte[] take(long timeoutMs) {
            long until = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < until) {
                byte[] p = toClient.poll();
                if (p != null) return p;
                synchronized (signal) {
                    try { signal.wait(50); } catch (InterruptedException e) { return null; }
                }
            }
            return null;
        }
    }

    /**
     * Синтетический TCP-клиент: собирает ответы, подтверждает полученные байты и
     * отправляет свои. Всё по-настоящему — номера, окна, флаги, суммы.
     */
    static class Client {
        final byte[] cliAddr = {10, 71, 71, 2};
        final byte[] srvAddr;
        final int cliPort, srvPort;
        final Tunnel tun;

        long cliSeq = 0x1234_5600L;          // наш ISN
        long srvExpected;                     // следующий ожидаемый серверный seq
        long uploaded;                        // байт данных уже отправлено
        final ByteArrayOutputStream rx = new ByteArrayOutputStream();

        int synAckSeen, finSeen, rstSeen, ackOnlySeen;
        long lastSrvSeq, lastSrvAck;
        int mssSeen, wscaleSeen = -1;
        final List<String> protocolErrors = new ArrayList<String>();

        Client(Tunnel tun, byte[] srvAddr, int srvPort) {
            this.tun = tun;
            this.srvAddr = srvAddr;
            this.srvPort = srvPort;
            this.cliPort = 51000;
        }

        /** Шаблон «изнутри наружу»: buildTcp разворачивает src/dst, поэтому тут они перевёрнуты. */
        Bits.Pkt template() {
            Bits.Pkt p = new Bits.Pkt();
            p.family = Bits.V4;
            p.proto = Bits.IPPROTO_TCP;
            p.src = srvAddr;
            p.dst = cliAddr;
            p.sport = srvPort;
            p.dport = cliPort;
            return p;
        }

        private Bits.Pkt parseIn(byte[] pkt) {
            Bits.Pkt p = Bits.parse(pkt, pkt.length);
            if (p == null) {
                protocolErrors.add("не разобрался ответ пакета");
                return null;
            }
            return p;
        }

        /** Обработать один пакет от TcpFlow; при наличии данных — подтвердить. */
        void accept(byte[] pkt) {
            Bits.Pkt p = parseIn(pkt);
            if (p == null) return;
            lastSrvSeq = p.seq;
            lastSrvAck = p.ackNum;
            int flags = p.flags;
            if ((flags & Bits.RST) != 0) { rstSeen++; return; }
            if ((flags & Bits.SYN) != 0) {
                synAckSeen++;
                srvExpected = (p.seq + 1) & 0xFFFFFFFFL;      // сервер подтвердил наш SYN + 1
                // запомним объявленные опции из TCP-заголовка
                wscaleSeen = p.wscale;
                return;
            }
            if (p.dataLen > 0) {
                if (p.seq != srvExpected) {
                    protocolErrors.add("данные не по порядку: seq=" + p.seq + " ждали " + srvExpected);
                } else {
                    rx.write(p.buf, p.dataOff, p.dataLen);
                    srvExpected = (srvExpected + p.dataLen) & 0xFFFFFFFFL;
                }
            } else {
                ackOnlySeen++;
            }
            if ((flags & Bits.FIN) != 0) finSeen++;
            // подтверждаем только принятые данные/FIN — как это делает настоящий TCP-стек
            if (p.dataLen > 0 || (flags & Bits.FIN) != 0) sendAck();
        }

        void sendAck() {
            byte[] pkt = Bits.buildTcp(template(), cliSeq + 1 + uploaded, srvExpected,
                    Bits.ACK, 65535, null, 0, 0, 0);
            tun.flow.onClientPacket(Bits.parse(pkt, pkt.length));
        }

        /** Отправить данные «в туннель» (как это сделало бы приложение телефона). */
        void sendData(byte[] data, int off, int len, boolean fin) {
            int flags = Bits.ACK | Bits.PSH;
            if (fin) flags |= Bits.FIN;
            byte[] pkt = Bits.buildTcp(template(), cliSeq + 1 + uploaded, srvExpected,
                    flags, 65535, data, off, len, 0);
            uploaded += len;
            tun.flow.onClientPacket(Bits.parse(pkt, pkt.length));
        }

        void sendSyn() {
            byte[] pkt = Bits.buildTcp(template(), cliSeq, 0, Bits.SYN, 65535, null, 0, 0,
                    Net.mss(false), 4);
            tun.flow.onClientPacket(Bits.parse(pkt, pkt.length));
        }

        byte[] received() { return rx.toByteArray(); }
    }

    /** Запустить поток и отдать его в клиентский цикл обработки пакетов. */
    static Client start(Tunnel tun, Profile profile, byte[] srvAddr, int srvPort) {
        tun.profile = profile;
        Client c = new Client(tun, srvAddr, srvPort);
        // SYN строим руками, чтобы parse увидел корректную длину
        byte[] synBytes = Bits.buildTcp(c.template(), c.cliSeq, 0, Bits.SYN, 65535, null, 0, 0,
                Net.mss(false), 4);
        Bits.Pkt syn = Bits.parse(synBytes, synBytes.length);
        tun.flow = new TcpFlow(tun.host(), syn, Bits.flowKey(Bits.IPPROTO_TCP, c.cliAddr,
                c.cliPort, srvAddr, srvPort));
        tun.flow.start();
        return c;
    }

    /** Вычитать пакеты от TcpFlow, пока не наберём нужное условие или не истечёт срок. */
    static boolean pump(Tunnel tun, Client c, long timeoutMs, Cond cond) {
        long until = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < until) {
            byte[] p = tun.take(until - System.currentTimeMillis());
            if (p == null) break;
            c.accept(p);
            if (cond != null && cond.done(c, tun)) return true;
        }
        return cond == null || cond.done(c, tun);
    }

    interface Cond { boolean done(Client c, Tunnel tun); }

    // ---------------------------------------------------------------- профиль для теста B

    /**
     * Профиль «как в APK» плюс одно правило на любое назначение, чтобы TLS-тест
     * доставался десинхронизацией (github в списки zapret не входит, и правильно делает).
     */
    static Profile productionProfile() throws Exception {
        Map<String, byte[]> fakes = new HashMap<String, byte[]>();
        Map<String, Config.HostSet> lists = new HashMap<String, Config.HostSet>();
        File pc = new File("app/assets/pc");
        File[] files = pc.listFiles();
        if (files == null) throw new IOException("нет app/assets/pc");
        for (File f : files) {
            byte[] data = Files.readAllBytes(f.toPath());
            String n = f.getName();
            if (n.endsWith(".bin")) fakes.put(Config.stripExt(n), data);
            else if (n.endsWith(".txt")) lists.put(Config.stripExt(n), Config.parseHostList(
                    Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)));
        }
        List<Config.Rule> rules = new ArrayList<Config.Rule>();
        for (String line : Files.readAllLines(Paths.get("app/assets/rules-exp.txt"),
                StandardCharsets.UTF_8)) {
            Config.Rule r = Config.parseRuleLine(line, fakes);
            if (r != null) rules.add(r);
        }
        // тестовое правило: TCP 443 на любое назначение, фрагментация + фейк, как в bat
        Config.Rule any = Config.parseRuleLine(
                "relay-tls|tcp|443|*|fake=tls_clienthello_www_sferum_ru.bin,split=1:4:1,ttl=8",
                fakes);
        if (any != null) rules.add(0, any);
        return Profile.build(lists, fakes, rules, "стенд");
    }

    static byte[] ipv4Of(String host) throws Exception {
        InetAddress[] all = InetAddress.getAllByName(host);
        for (InetAddress a : all) if (a instanceof Inet4Address) return a.getAddress();
        throw new IOException("нет IPv4 у " + host);
    }

    // ---------------------------------------------------------------- тесты

    /** Тест A: локальный эхо-сервер, 300 КБ туда-сюда, байт в байт. */
    static void testEcho300Kb() throws Exception {
        System.out.println("=== A. локальный эхо: 300 КБ через TcpFlow ===");
        final byte[] payload = new byte[300 * 1024];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i * 31 + 7);

        final ServerSocket ss = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
        final Thread server = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Socket s = ss.accept();
                    s.setTcpNoDelay(true);
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = s.getInputStream().read(buf)) > 0) {
                        s.getOutputStream().write(buf, 0, n);
                        s.getOutputStream().flush();
                    }
                    s.close();
                } catch (Exception e) {
                    System.out.println("  (эхо-сервер: " + e + ")");
                }
            }
        });
        server.setDaemon(true);
        server.start();

        Tunnel tun = new Tunnel();
        Profile p = productionProfile();
        Client c = start(tun, p, new byte[]{127, 0, 0, 1}, ss.getLocalPort());

        boolean synAck = pump(tun, c, 6000, new Cond() {
            @Override
            public boolean done(Client c, Tunnel tun) {
                return c.synAckSeen > 0;
            }
        });
        check("A: SYN/ACK получен", synAck && c.synAckSeen == 1, "synAck=" + c.synAckSeen);
        eq("A: SYN/ACK подтвердил наш SYN", c.lastSrvAck, (c.cliSeq + 1) & 0xFFFFFFFFL);
        check("A: объявлено окно с масштабом", c.wscaleSeen >= 0, "wscale=" + c.wscaleSeen);

        // отправляем по MSS
        int mss = Net.mss(false);
        int sent = 0;
        while (sent < payload.length) {
            final int n = Math.min(mss, payload.length - sent);
            final int off = sent;
            c.sendData(payload, off, n, false);
            sent += n;
            // понемного вычитываем ответы, чтобы окна не закрылись
            pump(tun, c, 200, new Cond() {
                @Override
                public boolean done(Client cc, Tunnel tt) {
                    return cc.rx.size() >= off + n;
                }
            });
        }
        boolean complete = pump(tun, c, 25_000, new Cond() {
            @Override
            public boolean done(Client cc, Tunnel tt) {
                return cc.rx.size() >= payload.length;
            }
        });
        byte[] got = c.received();
        check("A: все 300 КБ вернулись", complete && got.length == payload.length,
                "вернулось " + got.length + " из " + payload.length);
        int diffAt = -1;
        for (int i = 0; i < Math.min(got.length, payload.length); i++) {
            if (got[i] != payload[i]) { diffAt = i; break; }
        }
        check("A: байты в том же порядке", diffAt < 0, diffAt < 0 ? "" : "расхождение с " + diffAt);
        eq("A: RST не было", c.rstSeen, 0);
        check("A: пакеты клиенту с верными суммами",
                tun.badPackets.isEmpty(), String.valueOf(tun.badPackets));
        check("A: нет рассинхрона последовательностей",
                c.protocolErrors.isEmpty(), String.valueOf(c.protocolErrors));
        eq("A: bytesUp", tun.stats.bytesUp.get(), (long) payload.length);
        eq("A: bytesDown", tun.stats.bytesDown.get(), (long) payload.length);

        // закрываемся как клиент: FIN -> ждём FIN от потока
        c.sendData(new byte[0], 0, 0, true);
        boolean finBack = pump(tun, c, 8000, new Cond() {
            @Override
            public boolean done(Client cc, Tunnel tt) {
                return cc.finSeen > 0;
            }
        });
        check("A: на наш FIN ответили FIN (а не RST)", finBack && c.finSeen > 0,
                "fin=" + c.finSeen + " rst=" + c.rstSeen);
        ss.close();
    }

    /** Тест B: настоящий TLS через ретранслятор, поверх фрагментации и фейка. */
    static void testRealTls() throws Exception {
        System.out.println("=== B. настоящий TLS через TcpFlow (с десинхронизацией) ===");
        String host = "www.github.com";
        byte[] addr;
        try {
            addr = ipv4Of("github.com");
        } catch (Exception e) {
            System.out.println("  пропускаю: нет доступа к github.com (" + e + ")");
            return;
        }
        Tunnel tun = new Tunnel();
        Profile p = productionProfile();
        Client c = start(tun, p, addr, 443);
        pump(tun, c, 8000, new Cond() {
            @Override
            public boolean done(Client cc, Tunnel tt) {
                return cc.synAckSeen > 0;
            }
        });
        check("B: соединение с " + Bits.addrToString(addr) + ":443 установлено",
                c.synAckSeen > 0 && c.rstSeen == 0, "synAck=" + c.synAckSeen + " rst=" + c.rstSeen);
        if (c.synAckSeen == 0) return;

        // настоящий ClientHello: берём паттерн из APK и подставляем SNI нужной длины
        byte[] base = Files.readAllBytes(Paths.get("app/assets/pc/tls_clienthello_www_google_com.bin"));
        byte[] hello = Tls.withSni(base, host);
        eq("B: SNI в запросе подменён", Hello.sni(hello, 0, hello.length), host);

        // одним сегментом: дальше движок сам порежет его по точкам из правила
        c.sendData(hello, 0, hello.length, false);

        boolean anyData = pump(tun, c, 15_000, new Cond() {
            @Override
            public boolean done(Client cc, Tunnel tt) {
                return cc.rx.size() > 0;
            }
        });
        byte[] got = c.received();
        check("B: сервер что-то ответил", anyData && got.length > 0, "байт: " + got.length);

        boolean handshakeRecord = got.length >= 6 && got[0] == 0x16;      // Handshake
        check("B: пришёл TLS Handshake (ServerHello) — поток не испорчен десинхом",
                handshakeRecord, got.length > 0 ? "первый байт=" + (got[0] & 0xFF) : "пусто");
        if (handshakeRecord) {
            int recLen = ((got[3] & 0xFF) << 8) | (got[4] & 0xFF);
            check("B: длина записи правдоподобна", recLen > 0 && recLen < 16384, "len=" + recLen);
        }
        // дочитываем: сертификат обычно несколько записей
        pump(tun, c, 8000, new Cond() {
            @Override
            public boolean done(Client cc, Tunnel tt) {
                return cc.rx.size() > 8000;
            }
        });
        check("B: поток не обрывался (нет RST)", c.rstSeen == 0, "rst=" + c.rstSeen);
        check("B: сумм в пакетах не ломались", tun.badPackets.isEmpty(), String.valueOf(tun.badPackets));
        check("B: без рассинхрона последовательностей", c.protocolErrors.isEmpty(),
                String.valueOf(c.protocolErrors));
        check("B: десинхронизация засчитана", tun.stats.desyncTls.get() > 0,
                "desyncTls=" + tun.stats.desyncTls.get());
        // раньше на каждый чистый ACK прилетал ответный ACK: миллионы пакетов на один handshake
        check("B: нет шторма взаимных ACK", c.ackOnlySeen < 4000,
                "ack-only пакетов от потока: " + c.ackOnlySeen);
        System.out.println("  (получено " + c.received().length + " байт от сервера, "
                + "ACK-only пакетов " + c.ackOnlySeen + ")");
    }

    // ---------------------------------------------------------------- main

    public static void main(String[] args) throws Exception {
        System.out.println("стенд TCP-ретранслятора (чистый JVM, без Android)");
        try {
            testEcho300Kb();
        } catch (Exception e) {
            failed++;
            fails.add("тест A упал с исключением: " + e);
            e.printStackTrace();
        }
        try {
            testRealTls();
        } catch (Exception e) {
            failed++;
            fails.add("тест B упал с исключением: " + e);
            e.printStackTrace();
        }
        System.out.println();
        System.out.println("пройдено: " + passed + ", провалено: " + failed);
        for (String f : fails) System.out.println("  ! " + f);
        if (failed > 0) System.exit(1);
    }
}
