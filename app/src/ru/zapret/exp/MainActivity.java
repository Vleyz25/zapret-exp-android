package ru.zapret.exp;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.widget.CompoundButton;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.util.List;

/**
 * Один экран и один тумблер: включил — заработал перенесённый с ПК профиль general (EXP),
 * выключил — трафик идёт как раньше.
 */
public class MainActivity extends Activity {

    private Switch power;
    private TextView statusText;
    private TextView statsText;
    private TextView profileText;
    private TextView logText;
    private ScrollView logScroll;

    private static final int REQ_VPN = 20;
    private boolean pendingStart;
    private Profile profile;

    private final BroadcastReceiver tick = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            refresh();
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        setContentView(R.layout.main);

        power = findViewById(R.id.power_switch);
        statusText = findViewById(R.id.status_text);
        statsText = findViewById(R.id.stats_text);
        profileText = findViewById(R.id.profile_text);
        logText = findViewById(R.id.log_text);
        logScroll = findViewById(R.id.log_scroll);

        profile = Profile.load(this);
        StringBuilder sb = new StringBuilder();
        sb.append(getString(R.string.profile_name)).append('\n');
        sb.append(profile.summary).append('\n');
        for (Config.Rule r : profile.rules) {
            sb.append("  ").append(r.name)
                    .append(r.tcp && r.udp ? " tcp+udp" : (r.tcp ? " tcp" : " udp"))
                    .append(" порты ").append(java.util.Arrays.toString(r.portLo));
            if (r.fakeName != null) sb.append(" fake=").append(r.fakeName);
            if (r.splitPos > 0) sb.append(" split=").append(r.splitPos).append(':')
                    .append(r.splitRepeats).append(':').append(r.splitSkip);
            if (r.sni != null) sb.append(" sni=").append(r.sni);
            sb.append('\n');
        }
        profileText.setText(sb.toString());

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 10);
        }

        power.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton v, boolean checked) {
                if (checked) requestAndStart();
                else stopZapret();
            }
        });
    }

    private void requestAndStart() {
        Intent pre = VpnService.prepare(this);
        if (pre != null) {
            // Экран согласия системы — ждём его результат именно здесь. Раньше полагались
            // на onResume, и на некоторых оболочках (HiOS у Tecno) тумблер успевал
            // отжаться, пока диалог ещё не показан.
            pendingStart = true;
            statusText.setText(R.string.need_permission);
            try {
                startActivityForResult(pre, REQ_VPN);
            } catch (Exception e) {
                statusText.setText("Не удалось запросить разрешение: " + e);
                pendingStart = false;
                power.setChecked(false);
            }
        } else {
            startZapret();
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_VPN) return;
        pendingStart = false;
        if (res == RESULT_OK) {
            startZapret();
        } else {
            power.setChecked(false);
            ZapretService.lastError = "системный экран VPN-разрешения закрыт без согласия";
            refresh();
        }
    }

    private void startZapret() {
        Intent i = new Intent(this, ZapretService.class).setAction(ZapretService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i);
        else startService(i);
    }

    private void stopZapret() {
        startService(new Intent(this, ZapretService.class).setAction(ZapretService.ACTION_STOP));
        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        try {
            // Android 14 (targetSdk 34) требует явно указать экспорт при регистрации
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(tick, new IntentFilter(ZapretService.ACTION_TICK),
                        Context.RECEIVER_NOT_EXPORTED);
            } else {
                registerReceiver(tick, new IntentFilter(ZapretService.ACTION_TICK));
            }
        } catch (Exception ignored) { }
        if (!pendingStart) power.setChecked(ZapretService.running);
        if (pendingStart && VpnService.prepare(this) == null) {
            pendingStart = false;
            startZapret();
        }
        refresh();
    }

    @Override
    protected void onPause() {
        super.onPause();
        try {
            unregisterReceiver(tick);
        } catch (Exception ignored) { }
    }

    private void refresh() {
        boolean on = ZapretService.running;
        if (!pendingStart) power.setChecked(on);
        statusText.setText(on ? R.string.switch_on : R.string.switch_off);
        Stats s = ZapretService.liveStats;
        if (!on) {
            StringBuilder err = new StringBuilder();
            if (ZapretService.lastError != null) {
                err.append("Причина отказа: ").append(ZapretService.lastError).append('\n');
            }
            err.append("Выключено. Списков: ").append(profile.domainCount())
                    .append(" доменов, правил: ").append(profile.rules.size());
            statsText.setText(err.toString());
            if (s != null) showLog(s);
            // после отказа разблокируем тумблер, чтобы второй нажатие сработало
            if (!pendingStart) power.setChecked(false);
            return;
        }
        if (s == null) return;
        statsText.setText(String.format(getString(R.string.stats_format),
                s.tcpFlows.get(), s.udpFlows.get(), s.desyncTls.get(), s.desyncHttp.get(),
                s.desyncQuic.get(), profile.domainCount(),
                Bits.human(s.bytesDown.get()), Bits.human(s.bytesUp.get())));
        showLog(s);
    }

    /** Журнал показываем и в выключенном состоянии: в нём причина отказа. */
    private void showLog(final Stats s) {
        List<String> lines = s.logCopy();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(lines.size(), 40); i++) sb.append(lines.get(i)).append('\n');
        logText.setText(sb.toString());
        logScroll.post(new Runnable() {
            @Override
            public void run() {
                logScroll.fullScroll(android.view.View.FOCUS_DOWN);
            }
        });
    }

}
