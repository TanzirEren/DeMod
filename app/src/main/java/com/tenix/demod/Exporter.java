package com.tenix.demod;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.util.JsonWriter;
import androidx.core.content.FileProvider;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Exports findings as TXT / Markdown / HTML / JSON / CSV / patch / full ZIP bundle. */
final class Exporter {
    private Exporter() {}
    static final String[] FORMATS = {"Text report (.txt)", "Markdown (.md)", "HTML report (.html)", "JSON (.json)", "CSV (.csv)",
            "Patch of method changes (.diff)", "Full bundle (.zip: reports + added/changed files)"};

    private static String head(Project p) {
        return "DeMod report - " + p.name + "\nOriginal: " + p.origName + " (" + Util.size(p.origSize) + ")\nModified: " + p.modName
                + " (" + Util.size(p.modSize) + ")\nMod impact score: " + p.score + "/100 - " + Util.verdict(p.score) + "\n\n" + p.msg + "\n";
    }

    static File export(Context c, Project p, int fmt) throws IOException {
        Db db = Db.get(c);
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
        String base = p.name.replaceAll("[^A-Za-z0-9_-]", "_") + "_" + stamp;
        String[] ext = {"txt", "md", "html", "json", "csv", "diff", "zip"};
        File f = new File(Util.exportDir(c), base + "." + ext[fmt]);
        if (fmt == 6) { bundle(c, p, db, f); return f; }
        try (Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8), 1 << 16)) {
            write(fmt, p, db, w);
        }
        return f;
    }

    private static void write(int fmt, Project p, Db db, Writer w) throws IOException {
        switch (fmt) {
            case 0: txt(p, db, w); break;
            case 1: md(p, db, w); break;
            case 2: html(p, db, w); break;
            case 3: json(p, db, w); break;
            case 4: csv(db, p, w); break;
            default: patch(p, db, w);
        }
    }

    private static String cap(String s, int n) { return s != null && s.length() > n ? s.substring(0, n) + "\n...(truncated)" : s; }

    private static void txt(Project p, Db db, Writer w) throws IOException {
        w.write(head(p));
        try (Cursor c = db.all(p.id)) {
            String last = "";
            while (c.moveToNext()) {
                if (!c.getString(1).equals(last)) { last = c.getString(1); w.write("\n==================== " + Util.catLabel(last).toUpperCase(Locale.US) + " ====================\n"); }
                w.write("\n[" + Util.sevName(c.getInt(2)) + "] " + c.getString(3) + "\n" + c.getString(4) + "\n" + cap(c.getString(5), 20000).replace("@@DIFF@@", "---- DIFF ----") + "\n");
            }
        }
    }

    private static void md(Project p, Db db, Writer w) throws IOException {
        w.write("# " + p.name + "\n\n```\n" + head(p) + "```\n");
        try (Cursor c = db.all(p.id)) {
            String last = "";
            while (c.moveToNext()) {
                if (!c.getString(1).equals(last)) { last = c.getString(1); w.write("\n## " + Util.catLabel(last) + "\n"); }
                w.write("\n### [" + Util.sevName(c.getInt(2)) + "] " + c.getString(3).replace("\n", " ") + "\n```\n" + cap(c.getString(5), 12000).replace("```", "'''") + "\n```\n");
            }
        }
    }

    static String esc(String s) { return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }

    private static void html(Project p, Db db, Writer w) throws IOException {
        w.write("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>DeMod - " + esc(p.name) + "</title>"
                + "<style>body{font-family:system-ui,sans-serif;margin:0;background:#f4f7fb;color:#13202e}header{background:linear-gradient(135deg,#0f3f7a,#14a9c0);color:#fff;padding:24px}"
                + "main{padding:16px;max-width:1000px;margin:auto}details{background:#fff;border-radius:12px;margin:8px 0;padding:10px 14px;border-left:6px solid #94a3b8}"
                + ".s3{border-color:#e5484d}.s2{border-color:#f59e0b}.s1{border-color:#3b82f6}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;word-break:break-all;font-size:12px}"
                + "h2{margin-top:28px}.add{color:#16a34a}.del{color:#dc2626}</style><header><h1>DeMod report</h1><pre style='color:#fff'>" + esc(head(p)) + "</pre></header><main>");
        try (Cursor c = db.all(p.id)) {
            String last = "";
            while (c.moveToNext()) {
                if (!c.getString(1).equals(last)) { last = c.getString(1); w.write("<h2>" + esc(Util.catLabel(last)) + "</h2>"); }
                w.write("<details class=s" + c.getInt(2) + "><summary>[" + Util.sevName(c.getInt(2)) + "] " + esc(c.getString(3)) + "</summary><pre>");
                for (String l : cap(c.getString(5), 20000).replace("@@DIFF@@", "---- DIFF ----").split("\n")) {
                    String e = esc(l);
                    if (l.startsWith("+ ")) w.write("<span class=add>" + e + "</span>\n");
                    else if (l.startsWith("- ")) w.write("<span class=del>" + e + "</span>\n");
                    else w.write(e + "\n");
                }
                w.write("</pre></details>");
            }
        }
        w.write("</main>");
    }

    private static void json(Project p, Db db, Writer w) throws IOException {
        JsonWriter j = new JsonWriter(w);
        j.setIndent(" ");
        j.beginObject().name("project").value(p.name).name("original").value(p.origName).name("modified").value(p.modName)
                .name("score").value(p.score).name("summary").value(p.msg).name("findings").beginArray();
        try (Cursor c = db.all(p.id)) {
            while (c.moveToNext()) {
                j.beginObject().name("category").value(c.getString(1)).name("severity").value(Util.sevName(c.getInt(2)))
                        .name("title").value(c.getString(3)).name("subject").value(c.getString(4)).name("detail").value(cap(c.getString(5), 30000))
                        .name("bookmarked").value(c.getInt(6) == 1).endObject();
            }
        }
        j.endArray().endObject();
        j.flush();
    }

    private static String q(String s) { return "\"" + (s == null ? "" : s.replace("\"", "\"\"").replace("\n", " ")) + "\""; }

    private static void csv(Db db, Project p, Writer w) throws IOException {
        w.write("category,severity,title,subject\n");
        try (Cursor c = db.all(p.id)) {
            while (c.moveToNext()) w.write(q(c.getString(1)) + "," + Util.sevName(c.getInt(2)) + "," + q(c.getString(3)) + "," + q(c.getString(4)) + "\n");
        }
    }

    private static void patch(Project p, Db db, Writer w) throws IOException {
        w.write("# DeMod pseudo-smali patch for " + p.name + " (original -> modified)\n# registers omitted; for reading, not for applying\n\n");
        try (Cursor c = db.all(p.id)) {
            while (c.moveToNext()) {
                String d = c.getString(5);
                int i = d.indexOf("\n@@DIFF@@\n");
                if (i < 0) continue;
                String body = d.substring(i + 10);
                int e = body.indexOf("\n--- ORIGINAL ---");
                if (e >= 0) body = body.substring(0, e);
                w.write("--- a/" + c.getString(4) + "\n+++ b/" + c.getString(4) + "\n" + body + "\n");
            }
        }
    }

    private static void bundle(Context ctx, Project p, Db db, File out) throws IOException {
        try (ZipOutputStream z = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out), 1 << 16))) {
            String[] names = {"report.txt", "report.md", "report.html", "report.json", "findings.csv", "methods.diff"};
            for (int i = 0; i < names.length; i++) {
                z.putNextEntry(new ZipEntry(names[i]));
                Writer w = new OutputStreamWriter(z, StandardCharsets.UTF_8);
                write(i, p, db, w);
                w.flush();
                z.closeEntry();
            }
            File dir = Util.projDir(ctx, p.id), fo = new File(dir, "original.apk"), fm = new File(dir, "modified.apk");
            if (!fo.exists() || !fm.exists()) return;
            Map<String, ZipDiff.E> A = ZipDiff.read(fo), B = ZipDiff.read(fm);
            long total = 0;
            try (ZipFile zm = new ZipFile(fm)) {
                for (Map.Entry<String, ZipDiff.E> e : B.entrySet()) {
                    String n = e.getKey();
                    ZipDiff.E a = A.get(n), b = e.getValue();
                    if (n.startsWith("META-INF/")) continue;
                    boolean added = a == null, changed = a != null && (a.crc != b.crc || a.size != b.size);
                    if (!added && !changed) continue;
                    if (b.size > (25L << 20) || total + b.size > (400L << 20)) continue;
                    total += Math.max(0, b.size);
                    ZipEntry ze = zm.getEntry(n);
                    if (ze == null) continue;
                    z.putNextEntry(new ZipEntry("files/" + (added ? "added/" : "modified/") + n.replace("..", "_")));
                    try (InputStream in = zm.getInputStream(ze)) {
                        byte[] buf = new byte[1 << 16]; int k;
                        while ((k = in.read(buf)) > 0) z.write(buf, 0, k);
                    }
                    z.closeEntry();
                }
            }
        }
    }

    static void share(Context c, File f) {
        String name = f.getName();
        String mime = name.endsWith(".html") ? "text/html" : name.endsWith(".json") ? "application/json" : name.endsWith(".zip") ? "application/zip"
                : name.endsWith(".csv") ? "text/csv" : "text/plain";
        Uri u = FileProvider.getUriForFile(c, c.getPackageName() + ".files", f);
        Intent i = new Intent(Intent.ACTION_SEND).setType(mime).putExtra(Intent.EXTRA_STREAM, u).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        c.startActivity(Intent.createChooser(i, "Share / save report"));
    }
}
