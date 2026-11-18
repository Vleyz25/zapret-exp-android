package ru.zapret.exp;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Профиль «general (EXP)», перенесённый с ПК: загружает из APK списки доменов,
 * fake-паттерны и правила, а затем по ним подбирает приём десинхронизации.
 *
 * Списки и .bin-паттерны лежат в assets/pc — это файлы 1-в-1 из папки
 * zapret-discord-youtube-1.10.4; правила описаны в assets/rules-exp.txt.
 * Сам разбор конфига вынесен в Config (без Android-API), чтобы его можно было
 * тестировать на обычной JVM.
 */
public final class Profile {

    private static final String TAG = "Profile";

    public final List<Config.Rule> rules = new ArrayList<>();
    private final Map<String, Config.HostSet> hostLists = new HashMap<>();
    private final Map<String, byte[]> fakes = new HashMap<>();
    private Config.HostSet excludes;
    private int domainCount;
    public String summary = "";

    /** IP -> домен по нашим DNS-ответам: нужно для QUIC, где SNI зашифрован. */
    private final LinkedHashMap<String, String> ipToHost = new LinkedHashMap<String, String>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > 6000;
        }
    };

    /**
     * Сборка профиля из уже прочитанных данных. Чистый код без Android-API — поэтому
     * тесты на обычной JVM работают с ровно тем же конфигом, что лежит в APK.
     */
    public static Profile build(Map<String, Config.HostSet> lists, Map<String, byte[]> fakeMap,
                                List<Config.Rule> parsedRules, String label) {
        Profile p = new Profile();
        for (Map.Entry<String, Config.HostSet> e : lists.entrySet()) {
            hostListsPut(p, e.getKey(), e.getValue());
        }
        p.fakes.putAll(fakeMap);
        p.excludes = p.hostLists.get("zapret-exclude");
        for (Config.Rule r : parsedRules) {
            if (r.fakeName != null && r.fake == null) r.fake = null;     // фейк-файл пропал
            p.rules.add(r);
        }
        p.domainCount = 0;
        for (Config.HostSet hs : p.hostLists.values()) p.domainCount += hs.size();
        p.summary = (label == null ? "" : label + ", ") + "доменов: " + p.domainCount
                + ", fake-паттернов: " + p.fakes.size() + ", правил: " + p.rules.size();
        return p;
    }

    public static Profile load(Context ctx) {
        Profile p = new Profile();
        try {
            copyToFilesDir(ctx);

            Map<String, Config.HostSet> lists = new HashMap<>();
            Map<String, byte[]> fakeMap = new HashMap<>();
            for (String name : ctx.getAssets().list("pc")) {
                if (name.endsWith(".txt") && !name.startsWith("list-")) {
                    lists.put(Config.stripExt(name),
                            Config.parseHostList(readAssetLines(ctx, "pc/" + name)));
                } else if (name.endsWith(".bin")) {
                    fakeMap.put(Config.stripExt(name), readAssetBytes(ctx, "pc/" + name));
                }
            }
            // discord.media — как --hostlist-domains=discord.media в bat.
            if (!lists.containsKey("discordmedia")) {
                Config.HostSet dm = new Config.HostSet();
                dm.add("discord.media");
                lists.put("discordmedia", dm);
            }

            List<Config.Rule> parsed = new ArrayList<>();
            for (String line : readAssetLines(ctx, "rules-exp.txt")) {
                Config.Rule r = Config.parseRuleLine(line, fakeMap);
                if (r != null) parsed.add(r);
            }
            p = build(lists, fakeMap, parsed, null);
            Log.i(TAG, "профиль загружен: " + p.summary);
        } catch (Exception e) {
            Log.e(TAG, "не удалось загрузить профиль", e);
            p.summary = "профиль не загружен: " + e;
        }
        return p;
    }

    private static void hostListsPut(Profile p, String name, Config.HostSet hs) {
        p.hostLists.put(name.toLowerCase(), hs);
    }

    /** Правило для TCP-потока по порту назначения и хосту (SNI или Host). */
    public Config.Rule matchTcp(int dport, String host) {
        return Config.match(rules, hostLists, excludes, true, dport, host);
    }

    /**
     * Правило для UDP-потока. SNI в QUIC Initial зашифрован, поэтому совпадение по
     * доменному списку ищем по IP-адресу через карту из наших DNS-ответов
     * (аналог ipset у winws).
     */
    public Config.Rule matchUdp(int dport, byte[] dstIp) {
        // SNI в QUIC зашифрован -> хост ищем по IP через карту наших DNS-ответов
        return Config.match(rules, hostLists, excludes, false, dport, hostForIp(dstIp));
    }

    /**
     * Правило-образец для самопроверки: если для проверяемого хоста своего правила нет
     * (например, github в списки zapret не входит), берём первое tcp-правило с
     * фрагментацией — обычно general-main. Иначе проверка «с десинхом» ничего не проверяет.
     */
    public Config.Rule desyncSample() {
        for (Config.Rule r : rules) {
            if (r.name != null && r.name.equals("general-main") && r.tcp) return r;
        }
        for (Config.Rule r : rules) {
            if (r.tcp && r.splitPos > 0) return r;
        }
        return null;
    }

    public void learnDnsAnswer(String qname, List<byte[]> addrs) {
        if (qname == null || addrs.isEmpty()) return;
        synchronized (ipToHost) {
            for (byte[] a : addrs) ipToHost.put(Bits.addrToString(a), qname);
        }
    }

    public String hostForIp(byte[] ip) {
        String key = Bits.addrToString(ip);
        synchronized (ipToHost) {
            return ipToHost.get(key);
        }
    }

    public int domainCount() { return domainCount; }

    public int learnedHosts() {
        synchronized (ipToHost) {
            return ipToHost.size();
        }
    }

    // ---------- ввод ----------

    static List<String> readAssetLines(Context ctx, String path) throws Exception {
        List<String> out = new ArrayList<>();
        InputStream in = ctx.getAssets().open(path);
        try {
            BufferedReader rd = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = rd.readLine()) != null) out.add(line);
        } finally {
            in.close();
        }
        return out;
    }

    static byte[] readAssetBytes(Context ctx, String path) throws Exception {
        InputStream in = ctx.getAssets().open(path);
        try {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        } finally {
            in.close();
        }
    }

    /**
     * Копируем списки и fake-паттерны во внутренний каталог приложения: их видно
     * в файловом менеджере и можно править в том же формате, что на ПК.
     */
    private static void copyToFilesDir(Context ctx) {
        try {
            File dir = new File(ctx.getFilesDir(), "pc");
            if (!dir.exists()) dir.mkdirs();
            for (String name : ctx.getAssets().list("pc")) {
                File out = new File(dir, name);
                if (out.exists() && out.length() > 0) continue;
                InputStream in = ctx.getAssets().open("pc/" + name);
                try {
                    java.io.FileOutputStream fo = new java.io.FileOutputStream(out);
                    try {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) > 0) fo.write(buf, 0, n);
                    } finally {
                        fo.close();
                    }
                } finally {
                    in.close();
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "копирование списков в filesDir пропущено", e);
        }
    }
}
