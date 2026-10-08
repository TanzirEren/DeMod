package com.tenix.demod;

import android.app.Activity;
import android.content.Context;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import java.io.*;
import java.util.Locale;

final class Util {
    private Util() {}

    static final String[] CATS = {"PROTECTION", "BYPASS", "HOOK", "STRING", "DIALOG", "TOAST", "PERMISSION", "COMPONENT",
            "MANIFEST", "SIGNATURE", "FILE", "NATIVE", "NETWORK", "SDK", "CLASS", "METHOD", "RESOURCE", "INFO"};

    static String catLabel(String c) {
        switch (c) {
            case "PROTECTION": return "Pairip / Protection";
            case "BYPASS": return "Bypass";
            case "HOOK": return "Hooks / Injection";
            case "STRING": return "Strings";
            case "DIALOG": return "Dialogs";
            case "TOAST": return "Toasts";
            case "PERMISSION": return "Permissions";
            case "COMPONENT": return "Components";
            case "MANIFEST": return "Manifest";
            case "SIGNATURE": return "Signature";
            case "FILE": return "Files";
            case "NATIVE": return "Native libs";
            case "NETWORK": return "Network";
            case "SDK": return "SDKs";
            case "CLASS": return "Classes";
            case "METHOD": return "Methods";
            case "RESOURCE": return "Resources";
            case "INFO": return "Info";
            default: return c;
        }
    }

    static String sevName(int s) { return s >= 3 ? "HIGH" : s == 2 ? "MEDIUM" : s == 1 ? "LOW" : "INFO"; }

    static int sevColor(Context c, int s) {
        return ContextCompat.getColor(c, s >= 3 ? R.color.sev3 : s == 2 ? R.color.sev2 : s == 1 ? R.color.sev1 : R.color.sev0);
    }

    static String verdict(int score) {
        if (score < 8) return "Minimal changes";
        if (score < 30) return "Lightly modified";
        if (score < 60) return "Modified";
        if (score < 85) return "Heavily modified";
        return "Extensively modified";
    }

    static String size(long b) {
        if (b < 1024) return b + " B";
        double k = b / 1024.0;
        if (k < 1024) return String.format(Locale.US, "%.1f KB", k);
        double m = k / 1024;
        if (m < 1024) return String.format(Locale.US, "%.1f MB", m);
        return String.format(Locale.US, "%.2f GB", m / 1024);
    }

    static int dp(Context c, float v) { return Math.round(v * c.getResources().getDisplayMetrics().density); }

    static File projDir(Context c, long id) {
        File d = new File(c.getFilesDir(), "p" + id);
        d.mkdirs();
        return d;
    }

    static File exportDir(Context c) {
        File base = c.getExternalFilesDir(null);
        File d = new File(base != null ? base : c.getFilesDir(), "exports");
        d.mkdirs();
        return d;
    }

    static void deleteRec(File f) {
        if (f == null) return;
        File[] k = f.listFiles();
        if (k != null) for (File x : k) deleteRec(x);
        f.delete();
    }

    static String nameOf(Context c, Uri u) {
        try (Cursor q = c.getContentResolver().query(u, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (q != null && q.moveToFirst()) return q.getString(0);
        } catch (Exception ignored) { }
        String p = u.getLastPathSegment();
        return p == null ? "file.apk" : p;
    }

    static long sizeOf(Context c, Uri u) {
        try (Cursor q = c.getContentResolver().query(u, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (q != null && q.moveToFirst() && !q.isNull(0)) return q.getLong(0);
        } catch (Exception ignored) { }
        return 0;
    }

    static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) > 0) bo.write(b, 0, n);
        in.close();
        return bo.toString("UTF-8");
    }

    /** Applies the gradient header (title, subtitle, back button) and edge-to-edge insets. */
    static void header(Activity a, String title, String sub, boolean back) {
        WindowCompat.setDecorFitsSystemWindows(a.getWindow(), false);
        a.getWindow().setStatusBarColor(Color.TRANSPARENT);
        a.getWindow().setNavigationBarColor(Color.TRANSPARENT);
        WindowCompat.getInsetsController(a.getWindow(), a.getWindow().getDecorView()).setAppearanceLightStatusBars(false);
        final View hdr = a.findViewById(R.id.hdr);
        final int pl = hdr.getPaddingLeft(), pt = hdr.getPaddingTop(), pr = hdr.getPaddingRight(), pb = hdr.getPaddingBottom();
        ViewCompat.setOnApplyWindowInsetsListener(hdr, (v, ins) -> {
            Insets i = ins.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(pl, pt + i.top, pr, pb);
            return ins;
        });
        final View content = a.findViewById(android.R.id.content);
        ViewCompat.setOnApplyWindowInsetsListener(content, (v, ins) -> {
            Insets i = ins.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(0, 0, 0, i.bottom);
            return ins;
        });
        title(a, title, sub);
        View bb = a.findViewById(R.id.btnBack);
        if (back) { bb.setVisibility(View.VISIBLE); bb.setOnClickListener(v -> a.finish()); }
    }

    static void title(Activity a, String title, String sub) {
        ((TextView) a.findViewById(R.id.hdrTitle)).setText(title);
        TextView s = a.findViewById(R.id.hdrSub);
        s.setText(sub == null ? "" : sub);
        s.setVisibility(sub == null || sub.isEmpty() ? View.GONE : View.VISIBLE);
    }
}
