package ru.zapret.exp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Проверки ядра на обычной JVM (без Android и без телефона).
 * Запуск: см. run_tests.sh
 */
public class CoreTest {

    static int passed, failed;

    static void check(String name, boolean ok, String detail) {
        if (ok) {
            passed++;
            System.out.println("  ok   " + name);
        } else {
            failed++;
            System.out.println("  FAIL " + name + "  " + detail);
        }
    }

    static void eq(String name, Object a, Object b) {
        check(name, a.equals(b), "получено=" + a + " ожидалось=" + b);
    }

    public static void main(String[] args) throws Exception {
        String pc = args.length > 0 ? args[0] : "app/assets/pc";

        testParseSyn();
        testBuildChecksums();
        testPayloadRoundTrip();
        testSniFromPack(pc);
        testHttpHost();
        testDns();
        testSplits();
        testShippedConfig(pc);

        System.out.println();
        System.out.println("пройдено: " + passed + ", провалено: " + failed);
        if (failed > 0) System.exit(1);
    }

    // ---- 1. разбор IPv4 + TCP SYN ----
    static void testParseSyn() {
        byte[] p = new byte[40];
        p[0] = 0x45; p[2] = 0; p[3] = 40;
        p[8] = 64; p[9] = 6;
        p[12] = 10; p[13] = (byte) 128; p[14] = 0; p[15] = 2;      // клиент туннеля
        p[16] = (byte) 173; p[17] = (byte) 194; p[18] = (byte) 73; p[19] = 78; // youtube
        int t = 20;
        p[t] = (byte) 0xC0; p[t + 1] = 0x00;
        p[t + 2] = 0x01; p[t + 3] = (byte) 0xBB;                    // дпорт 443
        p[t + 4] = 0; p[t + 5] = 0; p[t + 6] = 0; p[t + 7] = 100;   // seq=100
        p[t + 12] = (byte) 0x50;                                    // dataOffset 20
        p[t + 13] = Bits.SYN;
        p[t + 14] = (byte) 0xFF; p[t + 15] = (byte) 0xFF;

        Bits.Pkt pk = Bits.parse(p, p.length);
        check("parse: пакет разобран", pk != null, "");
        if (pk == null) return;
        eq("parse: family", pk.family, Bits.V4);
        eq("parse: proto", pk.proto, Bits.IPPROTO_TCP);
        eq("parse: sport", pk.sport, 49152);
        eq("parse: dport", pk.dport, 443);
        eq("parse: seq", pk.seq, 100L);
        eq("parse: flags=SYN", pk.flags, Bits.SYN);
        eq("parse: window", pk.window, 0xFFFF);
        eq("parse: dataLen", pk.dataLen, 0);
        eq("parse: dst", Bits.addrToString(pk.dst), "173.194.73.78");
    }

    // ---- 2. контрольные суммы собранных пакетов ----
    static void testBuildChecksums() {
        Bits.Pkt in = fakeClientPacket("tls".getBytes(StandardCharsets.US_ASCII));
        byte[] out = Bits.buildTcp(in, 1000, 500, Bits.SYN | Bits.ACK, 65535, null, 0, 0, 1360);

        // IPv4: контрольная сумма заголовка обязана «схлопываться» в 0 при пересчёте
        eq("checksum: IPv4 заголовок валиден", Bits.checksum(out, 0, 20, 0), 0);
        int ihl = 20;
        int tcpLen = out.length - ihl;
        long seed = 0;
        for (int i = 12; i < 20; i += 2) seed += ((out[i] & 0xFF) << 8) | (out[i + 1] & 0xFF);
        seed += 6 + tcpLen;
        eq("checksum: TCP валиден", Bits.checksum(out, ihl, tcpLen, seed), 0);

        // SYN-ACK: ответы развёрнуты — отправитель = сервер, получатель = клиент
        eq("build: адрес сервера стал источником", Bits.addrToString(Bits.slice(out, 12, 4)), "173.194.73.78");
        eq("build: клиент стал получателем", Bits.addrToString(Bits.slice(out, 16, 4)), "10.128.0.2");
        eq("build: порт источника = порт назначения клиента", ((out[20] & 0xFF) << 8) | (out[21] & 0xFF), 443);
        eq("build: порт получателя = порт клиента", ((out[22] & 0xFF) << 8) | (out[23] & 0xFF), 49152);

        byte[] udp = Bits.buildUdp(in, "ответ".getBytes(StandardCharsets.UTF_8), 0, 10);
        eq("checksum: IPv4 (UDP) валиден", Bits.checksum(udp, 0, 20, 0), 0);
        long seed2 = 0;
        for (int i = 12; i < 20; i += 2) seed2 += ((udp[i] & 0xFF) << 8) | (udp[i + 1] & 0xFF);
        seed2 += 17 + (udp.length - 20);
        eq("checksum: UDP валиден", Bits.checksum(udp, 20, udp.length - 20, seed2), 0);
    }

    // ---- 3. данные доходят без изменений ----
    static void testPayloadRoundTrip() {
        Bits.Pkt in = fakeClientPacket(null);
        byte[] payload = new byte[3000];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xFF);
        byte[] out = Bits.buildTcp(in, 1, 2, Bits.ACK | Bits.PSH, 65535, payload, 0, payload.length, 0);
        Bits.Pkt back = Bits.parse(out, out.length);
        check("roundtrip: разбор собранного пакета", back != null, "");
        if (back == null) return;
        eq("roundtrip: длина данных", back.dataLen, payload.length);
        eq("roundtrip: MSS-опция не добавлена", back.headerLen, 20);
        byte[] got = Bits.slice(back.buf, back.dataOff, back.dataLen);
        check("roundtrip: байты совпадают", Arrays.equals(got, payload), "");
    }

    // ---- 4. SNI из настоящего fake-паттерна твоего пака ----
    static void testSniFromPack(String pc) throws Exception {
        byte[] sferum = Files.readAllBytes(Paths.get(pc, "tls_clienthello_www_sferum_ru.bin"));
        String sni = Hello.sni(sferum, 0, sferum.length);
        eq("sni: tls_clienthello_www_sferum_ru.bin", sni, "www.sferum.ru");
        eq("protocolOf: это TLS", Hello.protocolOf(sferum, 0, sferum.length), "tls");

        byte[] google = Files.readAllBytes(Paths.get(pc, "tls_clienthello_www_google_com.bin"));
        eq("sni: tls_clienthello_www_google_com.bin", Hello.sni(google, 0, google.length), "www.google.com");

        // подмена SNI (перенос --dpi-desync-hostfakesplit-mod) — при совпадении длины имени
        byte[] same = Tls.withSni(sferum, "www.sfereu.ru");
        eq("sni: withSni подменяет при той же длине", Hello.sni(same, 0, same.length), "www.sfereu.ru");
        byte[] other = Tls.withSni(sferum, "youtube.com");       // другая длина — шаблон как был
        eq("sni: withSni не ломает при другой длине", Hello.sni(other, 0, other.length), "www.sferum.ru");
    }

    // ---- 5. HTTP Host ----
    static void testHttpHost() {
        String req = "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com:443\r\nUser-Agent: x\r\n\r\n";
        byte[] b = req.getBytes(StandardCharsets.US_ASCII);
        eq("http: протокол", Hello.protocolOf(b, 0, b.length), "http");
        eq("http: Host", Hello.httpHost(b, 0, b.length), "www.gstatic.com");
    }

    // ---- 6. DNS ----
    static void testDns() {
        // запрос youtube.com (A)
        byte[] q = new byte[]{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
        eq("dns: имя запроса", Hello.dnsQueryName(q, 0, q.length), "youtube.com");

        // ответ с одной A-записью 203.0.113.77
        List<Byte> a = new ArrayList<>();
        for (byte x : q) a.add(x);
        a.set(6, (byte) 0); a.set(7, (byte) 1);        // QDCOUNT=1, ANCOUNT=... ниже
        a.set(8, (byte) 0); a.set(9, (byte) 1);
        // сжатое имя 0xC0 0x0C, type=1, class=1, ttl=64, rdlength=4
        byte[] rr = new byte[]{(byte) 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 64, 0, 4,
                (byte) 203, 0, 0x71, 77};
        byte[] full = new byte[a.size() + rr.length];
        for (int i = 0; i < a.size(); i++) full[i] = a.get(i);
        System.arraycopy(rr, 0, full, a.size(), rr.length);
        List<byte[]> addrs = Hello.dnsAnswerAddresses(full, 0, full.length);
        eq("dns: сколько адресов", addrs.size(), 1);
        eq("dns: адрес из ответа", Bits.addrToString(addrs.get(0)), "203.0.113.77");

        // AAAA-запись: 16 байт
        byte[] rr6 = new byte[]{(byte) 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 64, 0, 16,
                0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11};
        byte[] full6 = new byte[a.size() + rr6.length];
        for (int i = 0; i < a.size(); i++) full6[i] = a.get(i);
        System.arraycopy(rr6, 0, full6, a.size(), rr6.length);
        List<byte[]> addrs6 = Hello.dnsAnswerAddresses(full6, 0, full6.length);
        eq("dns: AAAA разобрана", addrs6.size(), 1);
        eq("dns: AAAA адрес", Bits.addrToString(addrs6.get(0)), "2001:0:0:0:0:0:0:11");
    }

    // ---- 7. фрагментация: байты не теряются и не дублируются ----
    static void testSplits() {
        int[] c = Splits.cuts(517, 1, 4, 1, "tls");
        check("splits: точки возрастают", increasing(c), Arrays.toString(c));
        eq("splits: покрытие байт = всего байт", covered(c, 517), 517);
        check("splits: есть разделение заголовка TLS (5)", contains(c, 5), Arrays.toString(c));

        int[] c2 = Splits.cuts(517, 1, 8, 1, "tls");
        // шаг skip=1 даёт позиции 1,3,5,7,9,11,13,15 — пятёрка уже среди них
        eq("splits: repeats=8 -> 8 точек", c2.length, 8);
        eq("splits: покрытие для repeats=8", covered(c2, 517), 517);

        int[] cTls = Splits.cuts(517, 1, 1, 0, "tls");
        eq("splits: TLS добавляет точку 5 (заголовок записи)", Arrays.toString(cTls), "[1, 5]");
        int[] cHttp = Splits.cuts(517, 1, 1, 0, "http");
        eq("splits: HTTP без точки 5", Arrays.toString(cHttp), "[1]");

        int[] c4 = Splits.cuts(3, 1, 4, 1, "tls");
        eq("splits: короткий запрос не ломается", covered(c4, 3), 3);

        // сумма сегментов равна длине полезной нагрузки для всех правил из профиля
        int[][] specs = {{1, 4, 1}, {1, 8, 1}, {1, 1, 0}};
        for (int[] s : specs) {
            for (int len = 1; len <= 1500; len++) {
                int[] cc = Splits.cuts(len, s[0], s[1], s[2], "tls");
                if (covered(cc, len) != len) {
                    check("splits: инвариант покрытия", false, "len=" + len + " spec=" + Arrays.toString(s));
                    return;
                }
            }
        }
        check("splits: инвариант покрытия выполнен для len 1..1500", true, "");
    }

    // ---- 8. конфигурация, которая реально лежит в APK ----
    static void testShippedConfig(String pc) throws Exception {
        java.nio.file.Path pcDir = Paths.get(pc);
        java.util.Map<String, byte[]> fakes = new java.util.HashMap<>();
        java.util.Map<String, Config.HostSet> lists = new java.util.HashMap<>();
        for (java.io.File f : pcDir.toFile().listFiles()) {
            if (f.isDirectory()) continue;
            byte[] data = Files.readAllBytes(f.toPath());
            String n = f.getName();
            if (n.endsWith(".bin")) {
                fakes.put(Config.stripExt(n), data);
            } else if (n.endsWith(".txt") && !n.startsWith("list-")) {
                lists.put(Config.stripExt(n), Config.parseHostList(
                        Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)));
            }
        }
        Config.HostSet excludes = lists.get("zapret-exclude");

        java.nio.file.Path rulesPath = pcDir.getParent().resolve("rules-exp.txt");
        List<Config.Rule> rules = new ArrayList<>();
        for (String line : Files.readAllLines(rulesPath, StandardCharsets.UTF_8)) {
            Config.Rule r = Config.parseRuleLine(line, fakes);
            if (r != null) rules.add(r);
        }
        eq("config: правил распарсено", rules.size(), 5);

        // 1) каждый fake=<файл> действительно существует в apk
        for (Config.Rule r : rules) {
            if (r.fakeName != null) {
                check("config: fake-файл есть у правила " + r.name,
                        r.fake != null && r.fake.length > 0, "fake=" + r.fakeName);
            }
        }

        // 2) списки с ПК читаются
        check("config: zapret-general непустой", lists.get("zapret-general").size() > 40,
                String.valueOf(lists.get("zapret-general").size()));
        check("config: zapret-google содержит youtube.com",
                lists.get("zapret-google").matches("youtube.com"), "");
        check("config: zapret-google содержит googlevideo",
                lists.get("zapret-google").matches("manifest.googlevideo.com"), "");
        check("config: zapret-general содержит discord.com",
                lists.get("zapret-general").matches("discord.com"), "");
        check("config: ^dns.google = точное совпадение",
                lists.get("zapret-general").matches("dns.google")
                        && !lists.get("zapret-general").matches("x.dns.google"), "");

        // 3) подбор правил как в winws: первое подошедшее
        Config.Rule rDiscord = Config.match(rules, lists, excludes, true, 443, "discord.com");
        check("config: tcp/443 discord.com -> общее правило", rDiscord != null
                && rDiscord.name.equals("general-main"), rDiscord == null ? "null" : rDiscord.name);
        Config.Rule rYt = Config.match(rules, lists, excludes, true, 443, "www.googlevideo.com");
        check("config: tcp/443 googlevideo -> google-правило", rYt != null
                && rYt.name.equals("google-youtube"), rYt == null ? "null" : rYt.name);
        check("config: tcp/443 twitch.tv -> ничего (не в списках)",
                Config.match(rules, lists, excludes, true, 443, "twitch.tv") == null, "");
        Config.Rule rCdn = Config.match(rules, lists, excludes, true, 2053, "discord.media");
        check("config: tcp/2053 discord.media -> cdn-правило", rCdn != null
                && rCdn.name.equals("discord-cdn"), rCdn == null ? "null" : rCdn.name);
        Config.Rule rQuic = Config.match(rules, lists, excludes, false, 443, "discord.com");
        check("config: udp/443 discord -> quic-фейк", rQuic != null
                && rQuic.name.equals("quic-general"), rQuic == null ? "null" : rQuic.name);
        check("config: udp/443 twitch -> не фейкаем (исключение/вне списков)",
                Config.match(rules, lists, excludes, false, 443, "twitch.tv") == null, "");
        Config.Rule rDucc = Config.match(rules, lists, excludes, false, 19300, null);
        check("config: udp/19300 -> discord-udp", rDucc != null
                && rDucc.name.equals("discord-udp"), rDucc == null ? "null" : rDucc.name);

        // 4) параметры, перенесённые из bat
        for (Config.Rule r : rules) {
            if (r.name.equals("quic-general")) {
                eq("config: quic repeat=11 (как --dpi-desync-repeats=11)", r.repeat, 11);
                eq("config: quic ttl=8", r.ttl, 8);
            }
            if (r.name.equals("general-main")) {
                eq("config: general-main split-pos", r.splitPos, 1);
                eq("config: general-main split-repeats", r.splitRepeats, 4);
            }
            if (r.name.equals("discord-udp")) {
                eq("config: discord-udp repeat=4", r.repeat, 4);
                check("config: discord-udp покрывает 19294-19344 и 50000-50100",
                        r.portsMatch(19294) && r.portsMatch(19344)
                                && r.portsMatch(50000) && r.portsMatch(50100)
                                && !r.portsMatch(443), r.ports());
            }
        }
    }

    static boolean increasing(int[] a) {
        for (int i = 1; i < a.length; i++) if (a[i] <= a[i - 1]) return false;
        return true;
    }

    static boolean contains(int[] a, int v) {
        for (int x : a) if (x == v) return true;
        return false;
    }

    /** Суммарное число байт, которое уйдёт сегментами, по точкам разбиения. */
    static int covered(int[] cuts, int len) {
        int total = 0, prev = 0;
        for (int c : cuts) {
            if (c > len) break;
            total += c - prev;
            prev = c;
        }
        total += len - prev;
        return total;
    }

    // ---- вспомогательное ----
    static Bits.Pkt fakeClientPacket(byte[] payload) {
        int plen = payload == null ? 0 : payload.length;
        byte[] p = new byte[40 + plen];
        p[0] = 0x45;
        p[2] = (byte) ((40 + plen) >> 8);
        p[3] = (byte) ((40 + plen) & 0xFF);
        p[9] = 6;
        p[12] = 10; p[13] = (byte) 128; p[15] = 2;             // 10.128.0.2
        p[16] = (byte) 173; p[17] = (byte) 194; p[18] = 73; p[19] = 78;
        p[20] = (byte) 0xC0; p[21] = 0;                        // sport 49152
        p[22] = 1; p[23] = (byte) 0xBB;                        // dport 443
        p[32] = (byte) 0x50;                                   // dataOffset
        p[33] = Bits.ACK;
        if (payload != null) System.arraycopy(payload, 0, p, 40, plen);
        Bits.Pkt pk = Bits.parse(p, p.length);
        if (pk == null) throw new IllegalStateException("не разберётся тестовый пакет");
        return pk;
    }
}
