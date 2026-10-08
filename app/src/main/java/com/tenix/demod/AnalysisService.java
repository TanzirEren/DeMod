package com.tenix.demod;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import androidx.core.app.NotificationCompat;

/** Foreground service: keeps big APK analyses alive while the app is in the background. */
public class AnalysisService extends Service {
    interface Listener { void onProgress(long pid, int pct, String msg); void onDone(long pid); }

    static volatile Listener listener;
    static volatile int pct;
    static volatile String msg = "";
    static volatile long running = -1;
    private static final Handler H = new Handler(Looper.getMainLooper());

    @Override public IBinder onBind(Intent i) { return null; }

    private Notification note(int p, String m) {
        return new NotificationCompat.Builder(this, "analysis").setSmallIcon(R.drawable.ic_apk).setContentTitle("DeMod - analyzing APKs")
                .setContentText(m).setProgress(100, p, p <= 0).setOngoing(true).setOnlyAlertOnce(true).build();
    }

    @Override public int onStartCommand(Intent i, int flags, int startId) {
        if (i == null) { stopSelf(); return START_NOT_STICKY; }
        final long pid = i.getLongExtra("pid", -1);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel("analysis", "Analysis", NotificationManager.IMPORTANCE_LOW);
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
        }
        Notification n = note(0, "Starting...");
        if (Build.VERSION.SDK_INT >= 29) startForeground(7, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        else startForeground(7, n);
        running = pid; pct = 0; msg = "Starting...";
        final NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        new Thread(() -> {
            Db db = Db.get(this);
            db.setStatus(pid, 1, "");
            try {
                new Analyzer(this, pid, (p, m) -> {
                    pct = p; msg = m;
                    nm.notify(7, note(p, m));
                    H.post(() -> { Listener l = listener; if (l != null) l.onProgress(pid, p, m); });
                }).run();
            } catch (Throwable t) {
                db.setStatus(pid, 3, t.getClass().getSimpleName() + ": " + t.getMessage());
            }
            running = -1;
            H.post(() -> { Listener l = listener; if (l != null) l.onDone(pid); });
            stopForeground(true);
            stopSelf();
        }, "demod-analyze").start();
        return START_NOT_STICKY;
    }
}
