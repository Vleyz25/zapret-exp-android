package ru.zapret.exp;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * UDP-поток: DNS, QUIC (YouTube/Discord по 443/udp) и голосовые диапазоны Discord.
 *
 * Здесь переносятся блоки EXP, работающие по UDP:
 *   --filter-l7=quic --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=...
 *   --filter-udp=19294-19344,50000-50100 --dpi-desync=fake --dpi-desync-repeats=4 ...
 * QUIC-датаграммы независимы (нет последовательности), поэтому фейковые датаграммы
 * уходят отдельно с малым TTL — это самый честный из перенесённых приёмов.
 */
public final class UdpFlow {

    private static final long IDLE_MS = 180_000;

    /**
     * Кэш DNS-ответов. Каждое новое соединение начинается с резолва, и без кэша мы
     * добавляем к нему полный к резолверу — это самые заметные «тормоза» при
     * включённом туннеле. Ответ отдаём сразу, подставив ID текущего запроса.
     * TTL берём свой (короткий), списки при этом обновляются как обычно.
     */
    private static final long DNS_TTL_MS = 120_000;
    private static final int DNS_CACHE_MAX = 200;
    private static final class Cached {
        final byte[] answer;
        final long expires;
        Cached(byte[] a, long e) { answer = a; expires = e; }
    }
    private static final Map<String, Cached> dnsCache = Collections.synchronizedMap(
            new LinkedHashMap<String, Cached>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry eldest) {
                    return size() > DNS_CACHE_MAX;
                }
            });

    public interface Host {
        void protectFd(FileDescriptor fd) throws Exception;
        void toTun(byte[] packet);
        Profile profile();
        Stats stats();
        void udpClosed(UdpFlow flow);
    }

    private final Host host;
    private final Bits.Pkt tmpl;
    private final FileDescriptor fd;
    private final InetSocketAddress dst;
    private final boolean v6;
    private final boolean realV6;
    private final String key, peer;
    private final int srvPort;

    private volatile boolean stopped;
    private volatile long lastActivity = System.currentTimeMillis();
    private volatile String dnsQueryName;
    private final Thread worker;

    public UdpFlow(Host host, Bits.Pkt first, String key, byte[] overrideDst) throws Exception {
        this.host = host;
        this.tmpl = first;
        this.key = key;
        this.v6 = first.family == Bits.V6;
        this.srvPort = first.dport;
        this.peer = Bits.addrToString(first.dst) + ":" + first.dport;
        // для DNS-запросов к нашему виртуальному серверу реально отправляем на вышестоящий resolver
        byte[] realDst = overrideDst != null ? overrideDst : first.dst;
        this.dst = new InetSocketAddress(Bits.toAddress(realDst), first.dport);
        this.realV6 = realDst.length == 16;
        fd = Os.socket(realV6 ? OsConstants.AF_INET6 : OsConstants.AF_INET, OsConstants.SOCK_DGRAM, 0);
        host.protectFd(fd);
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                runLoop();
            }
        }, "udp-" + peer);
        worker.setDaemon(true);
    }

    public void start() { worker.start(); }

    /** Первая датаграмма потока: по правилу EXP сначала уходят фейки, потом оригинал. */
    public void sendToServer(byte[] data, int off, int len, boolean first) {
        try {
            if (srvPort == 53) {
                dnsQueryName = Hello.dnsQueryName(data, off, len);
                if (answerFromCache(data, off, len)) return;
            }
            if (first) {
                Config.Rule r = host.profile().matchUdp(srvPort, tmpl.dst);
                if (r != null) {
                    if (r.drop) {
                        // прием «заблокировать QUIC»: приложение само уходит на TCP,
                        // где уже работает фрагментация
                        host.stats().log("QUIC отброшен [" + r.name + "] -> " + peer);
                        return;
                    }
                    if (r.fake != null || r.repeat > 0) {
                        Desync.udpFakes(realV6, dst, data, off, len, r, host.stats(), peer);
                    }
                }
            }
            Os.sendto(fd, data, off, len, 0, dst);
            host.stats().bytesUp.addAndGet(len);
            lastActivity = System.currentTimeMillis();
        } catch (Exception e) {
            host.stats().log("udp sendto " + peer + ": " + e);
            stop();
        }
    }

    private void runLoop() {
        StructPollfd pfd = new StructPollfd();
        pfd.fd = fd;
        byte[] buf = new byte[65536];
        InetSocketAddress from = new InetSocketAddress(0);
        try {
            while (!stopped) {
                pfd.events = (short) OsConstants.POLLIN;
                int pr = Os.poll(new StructPollfd[]{pfd}, 200);
                if (pr <= 0) {
                    if (System.currentTimeMillis() - lastActivity > IDLE_MS) break;
                    continue;
                }
                int n = Os.recvfrom(fd, buf, 0, buf.length, 0, from);
                if (n <= 0) continue;
                if (!from.getAddress().equals(dst.getAddress())) continue;   // чужой пакет
                if (srvPort == 53) {
                    learnDns(buf, n);
                    storeInCache(buf, n);
                }
                host.toTun(Bits.buildUdp(tmpl, buf, 0, n));
                host.stats().bytesDown.addAndGet(n);
                lastActivity = System.currentTimeMillis();
            }
        } catch (Exception e) {
            host.stats().log("udp поток " + peer + " закрыт: " + e);
        } finally {
            stop();
        }
    }

    /** True — ответ уже отправлен клиенту из кэша, дальше слать не нужно. */
    private boolean answerFromCache(byte[] req, int off, int len) {
        String key = Hello.dnsQuestionKey(req, off, len);
        if (key == null) return false;
        Cached c = dnsCache.get(key);
        if (c == null || System.currentTimeMillis() > c.expires) {
            if (c != null) dnsCache.remove(key);
            return false;
        }
        int qname = key.indexOf('|');
        String name = qname > 0 ? key.substring(0, qname) : key;
        byte[] copy = new byte[c.answer.length];
        System.arraycopy(c.answer, 0, copy, 0, copy.length);
        copy[0] = req[0];                             // ID запроса этого клиента
        copy[1] = req[1];
        host.toTun(Bits.buildUdp(tmpl, copy, 0, copy.length));
        host.stats().dnsCached.incrementAndGet();
        host.stats().bytesDown.addAndGet(copy.length);
        host.stats().log("dns кэш: " + name + " -> " + peer);
        lastActivity = System.currentTimeMillis();
        return true;
    }

    /** Кэшируем только успешные ответы с записями; ошибки и NXDOMAIN резолвим заново. */
    private static void storeInCache(byte[] b, int len) {
        try {
            if (len < 12) return;
            int rcode = b[3] & 0x0F;
            int ancount = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
            if (rcode != 0 || ancount == 0) return;
            String key = Hello.dnsQuestionKey(b, 0, len);
            if (key == null) return;
            byte[] copy = new byte[len];
            System.arraycopy(b, 0, copy, 0, len);
            dnsCache.put(key, new Cached(copy, System.currentTimeMillis() + DNS_TTL_MS));
        } catch (Exception ignored) { }
    }

    /** Запоминаем соответствие домен -> IP: нужно для правил QUIC, где SNI зашифрован. */
    private void learnDns(byte[] buf, int len) {
        try {
            List<byte[]> addrs = Hello.dnsAnswerAddresses(buf, 0, len);
            if (dnsQueryName != null && !addrs.isEmpty()) {
                host.profile().learnDnsAnswer(dnsQueryName, addrs);
                host.stats().dnsLearned.incrementAndGet();
            }
        } catch (Exception ignored) { }
    }

    public void stop() {
        if (stopped) return;
        stopped = true;
        try { Os.close(fd); } catch (Exception ignored) { }
        host.udpClosed(this);
    }

    public String key() { return key; }
}
