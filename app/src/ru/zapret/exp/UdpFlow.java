package ru.zapret.exp;

import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.FileDescriptor;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

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
                if (srvPort == 53) learnDns(buf, n);
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
