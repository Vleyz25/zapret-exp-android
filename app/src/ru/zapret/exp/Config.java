package ru.zapret.exp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Чистая (без Android-API) логика чтения конфига: списки доменов в синтаксисе zapret
 * и правила из assets/rules-exp.txt. Вынесено отдельно, чтобы конфигурацию можно было
 * проверить на обычной JVM (tests/CoreTest.java) — в том числе то, что каждый
 * fake=<файл> из правила действительно лежит в assets/pc.
 */
public final class Config {

    private Config() { }

    /** Один блок winws в нашем исполнении. */
    public static final class Rule {
        public String name;
        public boolean tcp, udp;
        public int[] portLo = new int[0];
        public int[] portHi = new int[0];
        public List<String> lists;          // null = любое назначение
        public byte[] fake;
        public String fakeName;
        public int repeat = 1;
        public int ttl = 8;
        public int splitPos = -1;
        public int splitRepeats = 1;
        public int splitSkip = 0;
        public String sni;
        public boolean drop;

        public boolean portsMatch(int port) {
            for (int i = 0; i < portLo.length; i++) {
                if (port >= portLo[i] && port <= portHi[i]) return true;
            }
            return false;
        }

        public String ports() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < portLo.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(portLo[i] == portHi[i] ? String.valueOf(portLo[i])
                        : portLo[i] + "-" + portHi[i]);
            }
            return sb.toString();
        }
    }

    /** Множество доменов в синтаксисе списков zapret. */
    public static final class HostSet {
        public final List<String> exact = new ArrayList<>();   // ^домен — только сам домен
        public final List<String> suffix = new ArrayList<>();  // домен — домен и поддомены

        public boolean matches(String host) {
            if (host == null) return false;
            String h = host.toLowerCase();
            for (String e : exact) if (e.equals(h)) return true;
            for (String s : suffix) {
                if (h.equals(s) || h.endsWith("." + s)) return true;
            }
            return false;
        }

        public void add(String entry) {
            String e = entry.trim().toLowerCase();
            int slash = e.indexOf('/');
            if (slash > 0) e = e.substring(0, slash);
            if (e.isEmpty() || e.startsWith("#") || e.startsWith(";")) return;
            if (e.startsWith("*.")) { suffix.add(e.substring(2)); return; }
            if (e.startsWith("^")) { exact.add(e.substring(1)); return; }
            suffix.add(e);
        }

        public int size() { return exact.size() + suffix.size(); }
    }

    public static HostSet parseHostList(List<String> lines) {
        HostSet hs = new HostSet();
        for (String l : lines) hs.add(l);
        return hs;
    }

    static int intSafe(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    /** Разбор одной строки правил. null — если строка пустая, комментарий или неполная. */
    public static Rule parseRuleLine(String line, Map<String, byte[]> fakes) {
        if (line == null) return null;
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return null;
        String[] f = trimmed.split("\\|");
        if (f.length < 5) return null;

        Rule r = new Rule();
        r.name = f[0].trim();
        String proto = f[1].trim().toLowerCase();
        r.tcp = proto.equals("tcp") || proto.equals("both");
        r.udp = proto.equals("udp") || proto.equals("quic") || proto.equals("both");
        if (!r.tcp && !r.udp) return null;
        parsePorts(f[2].trim(), r);
        String lists = f[3].trim();
        if (!lists.equals("*")) {
            r.lists = new ArrayList<>();
            for (String s : lists.split(",")) {
                if (!s.trim().isEmpty()) r.lists.add(s.trim().toLowerCase());
            }
        }
        for (String kv : f[4].split(",")) {
            String[] pair = kv.split("=", 2);
            if (pair.length != 2) continue;
            String k = pair[0].trim(), v = pair[1].trim();
            if (k.equals("fake")) {
                r.fakeName = v;
                r.fake = fakes.get(stripExt(v));
            } else if (k.equals("repeat")) {
                r.repeat = intSafe(v, 1);
            } else if (k.equals("ttl")) {
                r.ttl = intSafe(v, 8);
            } else if (k.equals("sni")) {
                r.sni = v;
            } else if (k.equals("drop")) {
                r.drop = intSafe(v, 0) != 0;
            } else if (k.equals("split")) {
                String[] sp = v.split(":");
                r.splitPos = intSafe(sp[0], 1);
                if (sp.length > 1) r.splitRepeats = intSafe(sp[1], 1);
                if (sp.length > 2) r.splitSkip = intSafe(sp[2], 0);
            }
        }
        return r;
    }

    public static void parsePorts(String spec, Rule r) {
        List<Integer> lo = new ArrayList<>(), hi = new ArrayList<>();
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            if (part.equals("*")) {
                lo.add(0); hi.add(65535);
                continue;
            }
            int dash = part.indexOf('-');
            if (dash > 0) {
                lo.add(intSafe(part.substring(0, dash), 0));
                hi.add(intSafe(part.substring(dash + 1), 65535));
            } else {
                int v = intSafe(part, 0);
                lo.add(v); hi.add(v);
            }
        }
        r.portLo = new int[lo.size()];
        r.portHi = new int[hi.size()];
        for (int i = 0; i < lo.size(); i++) {
            r.portLo[i] = lo.get(i);
            r.portHi[i] = hi.get(i);
        }
    }

    public static String stripExt(String n) {
        int dot = n.lastIndexOf('.');
        return dot > 0 ? n.substring(0, dot) : n;
    }

    /** Совпадение правила с хостом с учётом списков и исключений. */
    public static boolean ruleMatchesHost(Rule r, Map<String, HostSet> lists, HostSet excludes, String host) {
        if (r.lists == null) {
            return excludes == null || !excludes.matches(host);
        }
        if (host == null) return false;
        for (String name : r.lists) {
            HostSet hs = lists.get(name.toLowerCase());
            if (hs != null && hs.matches(host)) return true;
        }
        return false;
    }

    /**
     * Первое подходящее правило, как блоки winws, разделённые --new: перебор по порядку,
     * победил тот, у кого совпали порт и (протокол прикладного уровня) хост.
     */
    public static Rule match(List<Rule> rules, Map<String, HostSet> lists, HostSet excludes,
                             boolean wantTcp, int dport, String host) {
        for (Rule r : rules) {
            if ((wantTcp && !r.tcp) || (!wantTcp && !r.udp)) continue;
            if (!r.portsMatch(dport)) continue;
            if (ruleMatchesHost(r, lists, excludes, host)) return r;
        }
        return null;
    }
}
