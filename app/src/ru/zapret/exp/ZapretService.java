package ru.zapret.exp;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Туннель + движок. Локальный: ничего не шифруется и на чужие серверы не уходит,
 * это ровно то, что делает zapret на ПК, но в пользовательском пространстве, потому
 * что Android без root не даёт перехватывать пакеты через WinDivert/NFQUEUE.
 */
public class ZapretService extends VpnService
        implements TcpFlow.Host, UdpFlow.Host {

    private static final String TAG = "Zapret";

    public static final String ACTION_START = "ru.zapret.exp.START";
    public static final String ACTION_STOP = "ru.zapret.exp.STOP";
    public static final String ACTION_TICK = "ru.zapret.exp.TICK";

    private static final String TUN_IP_V4 = "10.71.71.2";
    private static final String TUN_DNS_V4 = "10.71.71.1";
    private static final String TUN_IP_V6 = "fd71:71::2";
    private static final String TUN_DNS_V6 = "fd71:71::1";
    private static final int MTU = 1400;
    private static final int NOTIF_ID = 1;
    private static final String CHANNEL = "tunel";

    public static volatile boolean running;
    /** Статистика активного сервиса, чтобы экран мог её показать. */
    public static volatile Stats liveStats;

    private ParcelFileDescriptor tun;
    private Thread reader;
    private final Map<String, TcpFlow> tcpFlows = new ConcurrentHashMap<>();
    private final Map<String, UdpFlow> udpFlows = new ConcurrentHashMap<>();
    private final Object tunLock = new Object();

    private Profile profile;
    private final Stats stats = new Stats();
    private final List<byte[]> upstreamDns = new ArrayList<>();
    private int dnsRotate;
    private Handler ticker;
    private volatile boolean stopRequested;

    // ---------------------------------------------------------------- жизненный цикл

    @Override
    public void onCreate() {
        super.onCreate();
        profile = Profile.load(this);
        setupChannel();
        discoverUpstreamDns();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            shutdown();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (running) return START_STICKY;

        startForegroundNotification();
        if (!openTunel()) {
            stopSelf();
            return START_NOT_STICKY;
        }
        running = true;
        liveStats = stats;
        stats.reset();
        stats.log("туннель поднят; профиль: general (EXP); " + profile.summary);
        stats.log("DNS вверх: " + (upstreamDns.isEmpty() ? "нет" : upstreamDns.size() + " серверов"));

        ticker = new Handler(Looper.getMainLooper());
        ticker.postDelayed(tick, 1000);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return SERVICE_INTERFACE.equals(intent == null ? null : intent.getAction())
                ? super.onBind(intent) : null;
    }

    @Override
    public void onRevoke() {
        stats.log("система отозвала VPN-разрешение");
        shutdown();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            if (!running) return;
            sendBroadcast(new Intent(ACTION_TICK).setPackage(getPackageName()));
            ticker.postDelayed(this, 1000);
        }
    };

    // ---------------------------------------------------------------- туннель

    private boolean openTunel() {
        try {
            Builder b = new Builder();
            b.setSession("Запрет (EXP)");
            b.addAddress(TUN_IP_V4, 32);
            b.addRoute("0.0.0.0", 0);
            b.addAddress(TUN_IP_V6, 64);
            b.addRoute("::", 0);
            b.addDnsServer(TUN_DNS_V4);
            b.addDnsServer(TUN_DNS_V6);
            b.setMtu(MTU);
            // Чтение из туннеля должно блокироваться, а не возвращать EAGAIN.
            // setBlocking появился в API 30, на более старых дефолт и так приемлемый.
            try {
                b.setBlocking(true);
            } catch (Throwable t) {
                Log.d(TAG, "setBlocking недоступен на этой версии Android");
            }
            disallowApplicationSelf(b);

            tun = b.establish();
            if (tun == null) {
                stats.log("не удалось поднять туннель (нет разрешения)");
                return false;
            }
            reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    readLoop();
                }
            }, "tun-read");
            reader.setDaemon(true);
            reader.start();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "establish()", e);
            stats.log("ошибка туннеля: " + e);
            return false;
        }
    }

    /** Наш собственный трафик не должен попадать в туннель (иначе кольцо). */
    private void disallowApplicationSelf(Builder b) {
        try {
            b.addDisallowedApplication(getPackageName());
        } catch (Exception ignored) { }
    }

    private void readLoop() {
        byte[] buf = new byte[MTU * 4];
        FileDescriptor fd = tun.getFileDescriptor();
        while (!stopRequested) {
            int n;
            try {
                n = Os.read(fd, buf, 0, buf.length);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EAGAIN) { sleepQuietly(); continue; }
                if (e.errno == OsConstants.EINTR) continue;
                if (!stopRequested) stats.log("туннель закрыт: " + Os.strerror(e.errno));
                break;
            } catch (Exception e) {
                if (!stopRequested) stats.log("чтение туннеля: " + e);
                break;
            }
            if (n <= 0) break;
            dispatch(buf, n);
        }
        running = false;
    }

    private void dispatch(byte[] buf, int len) {
        Bits.Pkt p;
        try {
            p = Bits.parse(buf, len);
        } catch (Exception e) {
            stats.dropped.incrementAndGet();
            return;
        }
        if (p == null) {
            stats.dropped.incrementAndGet();
            return;
        }
        // multicast/broadcast и адрес самого туннеля не релеим: на ПК winws их тоже не трогает
        if (isMulticast(p.dst) || isOurTunAddress(p.dst)) {
            stats.dropped.incrementAndGet();
            return;
        }
        if (p.proto == Bits.IPPROTO_TCP) {
            handleTcp(p);
        } else if (p.proto == Bits.IPPROTO_UDP) {
            handleUdp(p, len);
        } else {
            // ICMP и прочее не переносим: на ПК winws с этим не работает
            stats.dropped.incrementAndGet();
        }
    }

    private void handleTcp(Bits.Pkt p) {
        String key = Bits.flowKey(p.proto, p.src, p.sport, p.dst, p.dport);
        TcpFlow flow = tcpFlows.get(key);
        boolean syn = (p.flags & Bits.SYN) != 0 && (p.flags & Bits.ACK) == 0;

        if (flow == null) {
            if (!syn) {
                // поток уже умер или мы его не вели: сбрасываем, чтобы приложение не висело
                try {
                    toTun(Bits.buildTcp(p, p.ackNum, 0, Bits.RST | Bits.ACK, 0, null, 0, 0, 0));
                } catch (Exception ignored) { }
                stats.dropped.incrementAndGet();
                return;
            }
            if (tcpFlows.size() > 400) {
                // подчищаем завершённые потоки, иначе таблица разрастается
                for (Map.Entry<String, TcpFlow> e : new ArrayList<>(tcpFlows.entrySet())) {
                    if (e.getValue().isStopped()) tcpFlows.remove(e.getKey());
                }
            }
            if (tcpFlows.size() > 512) {
                stats.log("слишком много TCP-потоков, новый отклонён: "
                        + Bits.addrToString(p.dst) + ":" + p.dport);
                stats.dropped.incrementAndGet();
                return;
            }
            flow = new TcpFlow(this, p, key);
            tcpFlows.put(key, flow);
            stats.tcpFlows.incrementAndGet();
            flow.start();
            flow.onClientPacket(p);
            return;
        }
        if (flow.isStopped()) {
            // соединение уже закрыто, но клиент ещё досылает ACK/FIN — молча терпим,
            // иначе приложения увидят обрыв там, где всё закончилось нормально
            if (System.currentTimeMillis() - flow.closedAt() < TcpFlow.GRACE_MS) return;
            tcpFlows.remove(key);
            try {
                toTun(Bits.buildTcp(p, p.ackNum, 0, Bits.RST | Bits.ACK, 0, null, 0, 0, 0));
            } catch (Exception ignored) { }
            stats.dropped.incrementAndGet();
            return;
        }
        flow.onClientPacket(p);
    }

    private void handleUdp(Bits.Pkt p, int len) {
        String key = Bits.flowKey(p.proto, p.src, p.sport, p.dst, p.dport);
        UdpFlow flow = udpFlows.get(key);
        boolean isNew = flow == null;
        if (isNew) {
            if (udpFlows.size() > 512) {
                stats.dropped.incrementAndGet();
                return;
            }
            try {
                byte[] override = null;
                // Запросы к нашему «виртуальному» DNS отправляем на настоящий resolver
                if (p.dport == 53 && isOurDns(p.dst)) {
                    override = pickUpstreamDns();
                    if (override == null) {
                        stats.log("нет вышестоящего DNS");
                        stats.dropped.incrementAndGet();
                        return;
                    }
                    key = Bits.flowKey(p.proto, p.src, p.sport, override, p.dport);
                    flow = udpFlows.get(key);
                    if (flow != null) {
                        flow.sendToServer(p.buf, p.dataOff, p.dataLen, false);
                        return;
                    }
                    isNew = true;
                }
                flow = new UdpFlow(this, p, key, override);
            } catch (Exception e) {
                stats.log("udp поток: " + e);
                stats.dropped.incrementAndGet();
                return;
            }
            udpFlows.put(key, flow);
            stats.udpFlows.incrementAndGet();
            flow.start();
        }
        flow.sendToServer(p.buf, p.dataOff, p.dataLen, isNew);
    }

    /** 224.0.0.0/4, ff00::/12 — групповые адреса не переносим. */
    private static boolean isMulticast(byte[] a) {
        if (a.length == 4) {
            int b0 = a[0] & 0xFF;
            if (b0 >= 224 && b0 < 240) return true;
            return b0 == 255;                               // 255.255.255.255
        }
        return (a[0] & 0xFF) == 0xFF;                        // ff00::/12
    }

    private boolean isOurTunAddress(byte[] a) {
        try {
            return Bits.sameAddr(a, InetAddress.getByName(TUN_IP_V4).getAddress())
                    || Bits.sameAddr(a, InetAddress.getByName(TUN_IP_V6).getAddress());
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isOurDns(byte[] a) {
        try {
            return Bits.sameAddr(a, InetAddress.getByName(TUN_DNS_V4).getAddress())
                    || Bits.sameAddr(a, InetAddress.getByName(TUN_DNS_V6).getAddress());
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] pickUpstreamDns() {
        if (upstreamDns.isEmpty()) return null;
        byte[] a = upstreamDns.get(dnsRotate % upstreamDns.size());
        dnsRotate++;
        return a;
    }

    private void discoverUpstreamDns() {
        upstreamDns.clear();
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            Network net = cm.getActiveNetwork();
            if (net != null) {
                LinkProperties lp = cm.getLinkProperties(net);
                if (lp != null) {
                    for (InetAddress d : lp.getDnsServers()) {
                        upstreamDns.add(d.getAddress());
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "dns из системы не получен", e);
        }
        if (upstreamDns.isEmpty()) {
            // система ничего не подсказала: берём публичные резолверы
            try {
                upstreamDns.add(InetAddress.getByName("1.1.1.1").getAddress());
                upstreamDns.add(InetAddress.getByName("8.8.8.8").getAddress());
            } catch (Exception ignored) { }
        }
        // Если системный DNS найден, именно он и используется: zapret на ПК адрес DNS
        // не меняет, поэтому и здесь не подменяем — иначе CDN начали бы отдавать
        // другие IP, а это уже поведение не «как на компьютере».
    }

    // ---------------------------------------------------------------- интерфейс потоков

    @Override
    public void toTun(byte[] packet) {
        synchronized (tunLock) {
            try {
                if (tun != null) Os.write(tun.getFileDescriptor(), packet, 0, packet.length);
            } catch (Exception e) {
                stats.log("запись в туннель: " + e);
            }
        }
    }

    /**
     * Защита собственного трафика от попадания в туннель.
     *
     * VpnService.protect() принимает только int/Socket/DatagramSocket, а движок работает
     * с файловыми дескрипторами android.system.Os. Поэтому вместо protect используется
     * addDisallowedApplication(наш пакет) — весь трафик приложения, включая сокеты,
     * созданные через Os.socket(), идёт мимо туннеля. Это же снимает нужность
     * привилегированных вызовов.
     */
    @Override
    public void protectFd(FileDescriptor fd) throws Exception {
        // намеренно ничего не делаем: наш пакет исключён из туннеля в openTunel()
    }

    @Override
    public Profile profile() { return profile; }

    @Override
    public Stats stats() { return stats; }

    @Override
    public void udpClosed(UdpFlow flow) { udpFlows.remove(flow.key()); }

    // ---------------------------------------------------------------- остановка

    private void shutdown() {
        stopRequested = true;
        running = false;
        liveStats = stats;
        if (ticker != null) ticker.removeCallbacksAndMessages(null);
        for (TcpFlow f : new ArrayList<>(tcpFlows.values())) f.close(true);
        for (UdpFlow f : new ArrayList<>(udpFlows.values())) f.stop();
        tcpFlows.clear();
        udpFlows.clear();
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) { }
            tun = null;
        }
        stats.log("туннель остановлен");
    }

    private void sleepQuietly() {
        try { Thread.sleep(5); } catch (InterruptedException ignored) { }
    }

    // ---------------------------------------------------------------- уведомление

    private void setupChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            NotificationChannel ch = new NotificationChannel(CHANNEL,
                    getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private void startForegroundNotification() {
        Intent i = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, i,
                Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        Notification.Builder nb = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL)
                : new Notification.Builder(this);
        Notification n = nb.setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.notif_running))
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        } else {
            startForeground(NOTIF_ID, n);
        }
    }

    /** Статистика для интерфейса. */
    public Stats currentStats() { return stats; }
}
