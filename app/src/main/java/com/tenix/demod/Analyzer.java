package com.tenix.demod;

import android.content.Context;
import android.net.Uri;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONArray;
import org.json.JSONObject;

/** Orchestrates the whole APK-vs-APK comparison and turns raw diffs into explained findings. */
final class Analyzer {
    static final class F { String cat, title, sub, detail; int sev; }
    static final class Rule { String id, scope, cat, label; int sev; Pattern re; }
    interface CB { void p(int pct, String msg); }

    private static final int MAX_F = 120000;
    private static final Pattern INVOKE = Pattern.compile("^invoke-\\S+ (L[^;]+;)->(\\S+)");
    private static final Pattern KW_PROT = Pattern.compile("(?i)(integrity|signature|tamper|licen[sc]|checksum|pairip|isroot|emulator|debugg|verify|validate)");
    private static final Pattern KW_BYP = Pattern.compile("(?i)(premium|\\bpro\\b|ispro|vip|subscri|purchas|billing|unlock|paid|adfree|noads|removead|entitle|trial|isads|showads|hasads)");
    private static final String[][] SDKS = {
            {"Google Mobile Ads (AdMob)", "Lcom/google/android/gms/ads/"}, {"Facebook Audience Network", "Lcom/facebook/ads/"},
            {"Unity Ads", "Lcom/unity3d/ads/"}, {"AppLovin", "Lcom/applovin/"}, {"ironSource", "Lcom/ironsource/"},
            {"Vungle", "Lcom/vungle/"}, {"Chartboost", "Lcom/chartboost/"}, {"Mintegral", "Lcom/mbridge/"},
            {"Pangle (ByteDance)", "Lcom/bytedance/sdk/openadsdk/"}, {"InMobi", "Lcom/inmobi/"}, {"AdColony", "Lcom/adcolony/"},
            {"Firebase Analytics", "Lcom/google/firebase/analytics/"}, {"Firebase Crashlytics", "Lcom/google/firebase/crashlytics/"},
            {"AppsFlyer", "Lcom/appsflyer/"}, {"Adjust", "Lcom/adjust/sdk/"}, {"OneSignal", "Lcom/onesignal/"}, {"Sentry", "Lio/sentry/"},
            {"Google Play Billing", "Lcom/android/billingclient/"}, {"Play Integrity", "Lcom/google/android/play/core/integrity/"},
            {"Play Licensing (LVL)", "Lcom/google/android/vending/licensing/"}, {"Pairip", "Lcom/google/android/apps/play/pairip/"}};
    private static final Set<String> DANGER = new HashSet<>(Arrays.asList(
            "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS", "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS", "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.QUERY_ALL_PACKAGES", "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.WRITE_SETTINGS", "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.READ_CALL_LOG", "android.permission.REQUEST_DELETE_PACKAGES"));
    private static final Map<String, String> PERM_INFO = new HashMap<>();
    static {
        PERM_INFO.put("android.permission.SYSTEM_ALERT_WINDOW", "Draw over other apps - used by floating mod menus / overlay dialogs.");
        PERM_INFO.put("android.permission.REQUEST_INSTALL_PACKAGES", "Can ask to install other APKs.");
        PERM_INFO.put("android.permission.MANAGE_EXTERNAL_STORAGE", "All-files access.");
        PERM_INFO.put("android.permission.QUERY_ALL_PACKAGES", "Can list every installed app.");
        PERM_INFO.put("android.permission.BIND_ACCESSIBILITY_SERVICE", "Accessibility service (can read/click the screen).");
        PERM_INFO.put("android.permission.INTERNET", "Network access.");
        PERM_INFO.put("com.android.vending.BILLING", "Google Play Billing - removal is common in premium-unlock mods.");
        PERM_INFO.put("com.android.vending.CHECK_LICENSE", "Play license check permission.");
    }

    private final Context ctx;
    private final long pid;
    private final CB cb;
    private final Db db;
    private final List<F> out = new ArrayList<>();
    private List<Rule> rules = new ArrayList<>();
    private final List<String> addedPerms = new ArrayList<>();
    private final StringBuilder notes = new StringBuilder();
    private int fAdd, fRem, fMod, pAdd, pRem, plain, hookN, addedFind;
    private long[] cnt = new long[7];

    Analyzer(Context c, long pid, CB cb) {
        this.ctx = c; this.pid = pid; this.cb = cb; this.db = Db.get(c);
    }

    private void add(String cat, int sev, String title, String sub, String detail) {
        if (out.size() >= MAX_F) return;
        F f = new F();
        f.cat = cat; f.sev = sev; f.title = title; f.sub = sub;
        f.detail = detail != null && detail.length() > 100000 ? detail.substring(0, 100000) + "\n...(truncated)" : detail;
        out.add(f);
    }

    void run() throws Exception {
        Project p = db.project(pid);
        File dir = Util.projDir(ctx, pid);
        File fo = new File(dir, "original.apk"), fm = new File(dir, "modified.apk");
        db.clearFindings(pid);
        long tot = Math.max(1, p.origSize + p.modSize);
        long[] done = {0};
        copyUri(Uri.parse(p.origUri), fo, done, tot, "Copying original APK");
        copyUri(Uri.parse(p.modUri), fm, done, tot, "Copying modified APK");
        loadRules();
        notes.append("Native engine: ").append(NativeBridge.ok ? NativeBridge.version() : "NOT LOADED (DEX analysis skipped)").append('\n');

        cb.p(26, "Comparing ZIP structure");
        Map<String, ZipDiff.E> A = ZipDiff.read(fo), B = ZipDiff.read(fm);
        notes.append("Entries: original ").append(A.size()).append(", modified ").append(B.size()).append('\n');
        fileDiff(A, B);
        cb.p(34, "Reading manifests");
        manifestDiff(fo, fm);
        cb.p(38, "Comparing signing certificates");
        signatureDiff(fo, fm);
        cb.p(42, "Comparing resources.arsc strings");
        arscDiff(fo, fm);
        cb.p(46, "Analyzing DEX with native engine");
        dexDiff(fo, fm, A, B, dir);
        cb.p(88, "Scanning native libraries");
        nativeDiff(fo, fm, A, B, dir);
        cb.p(94, "Scoring and saving");
        add("INFO", 0, "Analysis notes", "engine, coverage, limits", notes.toString()
                + "\nHeuristics: bypass / protection / hook detections are pattern based and can have false positives or misses.\n"
                + "Pseudo-smali omits registers and branch offsets so that register renaming does not look like a change.\n"
                + "v2/v3 signing blocks are not parsed; only the v1 (META-INF) certificate is compared.\n"
                + "Rules live in rules.json (assets, or imported from the main menu).");
        int[] sc = new int[4];
        for (F f : out) sc[Math.min(3, Math.max(0, f.sev))]++;
        int score = (int) Math.min(100, Math.round(sc[3] * 6.0 + sc[2] * 2.0 + sc[1] * 0.3));
        StringBuilder s = new StringBuilder();
        s.append("Files: +").append(fAdd).append("  -").append(fRem).append("  ~").append(fMod).append('\n');
        s.append("Permissions: +").append(pAdd).append("  -").append(pRem).append('\n');
        s.append("Classes: +").append(cnt[0]).append("  -").append(cnt[1]).append("   Methods: +").append(cnt[2]).append("  -").append(cnt[3]).append("  ~").append(cnt[4]).append('\n');
        s.append("Code strings: +").append(cnt[5]).append("  -").append(cnt[6]).append('\n');
        Map<String, Integer> byCat = new TreeMap<>();
        for (F f : out) if (f.sev >= 2) byCat.merge(f.cat, 1, Integer::sum);
        s.append("Medium/High findings: ");
        if (byCat.isEmpty()) s.append("none");
        for (Map.Entry<String, Integer> e : byCat.entrySet()) s.append(Util.catLabel(e.getKey())).append(' ').append(e.getValue()).append("   ");
        db.insertFindings(pid, out);
        db.finish(pid, score, s.toString());
        cb.p(100, "Done");
    }

    // ---------------------------------------------------------------- copying
    private void copyUri(Uri u, File dst, long[] done, long tot, String msg) throws IOException {
        try (InputStream in = ctx.getContentResolver().openInputStream(u);
             OutputStream o = new BufferedOutputStream(new FileOutputStream(dst), 1 << 18)) {
            if (in == null) throw new IOException("Cannot open " + u);
            byte[] buf = new byte[1 << 18]; int n; long last = 0;
            while ((n = in.read(buf)) > 0) {
                o.write(buf, 0, n);
                done[0] += n;
                if (done[0] - last > (4 << 20)) { last = done[0]; cb.p((int) Math.min(24, done[0] * 24 / tot) + 1, msg + " (" + Util.size(done[0]) + ")"); }
            }
        }
    }

    // ---------------------------------------------------------------- rules
    private void loadRules() {
        rules = new ArrayList<>();
        try {
            File cf = new File(ctx.getFilesDir(), "rules.json");
            InputStream in = cf.exists() ? new FileInputStream(cf) : ctx.getAssets().open("rules.json");
            JSONArray a = new JSONArray(Util.readAll(in));
            for (int i = 0; i < a.length(); i++) {
                try {
                    JSONObject o = a.getJSONObject(i);
                    Rule r = new Rule();
                    r.id = o.optString("id"); r.scope = o.optString("scope"); r.cat = o.optString("cat", "INFO");
                    r.label = o.optString("label", r.id); r.sev = o.optInt("sev", 1);
                    r.re = Pattern.compile(o.getString("re"));
                    rules.add(r);
                } catch (Exception e) { notes.append("Bad rule #").append(i).append(": ").append(e.getMessage()).append('\n'); }
            }
            notes.append("Rules loaded: ").append(rules.size()).append('\n');
        } catch (Exception e) { notes.append("rules.json error: ").append(e).append('\n'); }
    }

    // ---------------------------------------------------------------- files
    private void fileDiff(Map<String, ZipDiff.E> A, Map<String, ZipDiff.E> B) {
        List<String> ad = new ArrayList<>(), rm = new ArrayList<>(), md = new ArrayList<>();
        for (Map.Entry<String, ZipDiff.E> e : B.entrySet()) {
            ZipDiff.E a = A.get(e.getKey());
            if (a == null) ad.add(e.getKey());
            else if (a.crc != e.getValue().crc || a.size != e.getValue().size) md.add(e.getKey());
        }
        for (String k : A.keySet()) if (!B.containsKey(k)) rm.add(k);
        Collections.sort(ad); Collections.sort(rm); Collections.sort(md);
        fAdd = ad.size(); fRem = rm.size(); fMod = md.size();
        emitFiles("+", ad, A, B); emitFiles("-", rm, A, B); emitFiles("~", md, A, B);
    }

    private void emitFiles(String sign, List<String> names, Map<String, ZipDiff.E> A, Map<String, ZipDiff.E> B) {
        String scope = sign.equals("+") ? "addedFile" : sign.equals("-") ? "removedFile" : "modifiedFile";
        String status = sign.equals("+") ? "ADDED in modified APK" : sign.equals("-") ? "REMOVED from modified APK" : "MODIFIED";
        int shown = 0;
        for (String n : names) {
            ZipDiff.E a = A.get(n), b = B.get(n);
            StringBuilder det = new StringBuilder("Path    : " + n + "\nStatus  : " + status + "\n");
            if (a != null) det.append("Original : ").append(Util.size(a.size)).append("  crc32 ").append(Long.toHexString(a.crc)).append('\n');
            if (b != null) det.append("Modified : ").append(Util.size(b.size)).append("  crc32 ").append(Long.toHexString(b.crc)).append('\n');
            for (Rule r : rules)
                if (r.scope.equals(scope) && r.re.matcher(n).find())
                    add(r.cat, r.sev, r.label + ": " + n, sign + " " + n, det + "Rule    : " + r.id + "\n");
            if (n.startsWith("META-INF/") || shown >= 3000) continue;
            shown++;
            boolean so = n.endsWith(".so"), dex = n.matches("classes\\d*\\.dex");
            int sev = sign.equals("+") ? ((dex || so) ? 2 : 1) : sign.equals("-") ? 1 : ((dex || so || n.equals("resources.arsc")) ? 1 : 0);
            String sub = sign.equals("~") ? Util.size(a.size) + " -> " + Util.size(b.size) : Util.size((b != null ? b : a).size);
            add(so ? "NATIVE" : "FILE", sev, sign + " " + n, sub, det.toString());
        }
        if (names.size() > shown + 0 && shown >= 3000) add("FILE", 0, "... " + (names.size() - shown) + " more " + status.toLowerCase(Locale.US) + " files not listed", "", "Only the first 3000 entries per group are listed.");
    }

    // ---------------------------------------------------------------- manifest
    private void manifestDiff(File fo, File fm) {
        try {
            byte[] a = ZipDiff.entryBytes(fo, "AndroidManifest.xml", 64L << 20), b = ZipDiff.entryBytes(fm, "AndroidManifest.xml", 64L << 20);
            if (a == null || b == null) { notes.append("AndroidManifest.xml not readable\n"); return; }
            Axml.Manifest x = Axml.parse(a), y = Axml.parse(b);
            Set<String> keys = new TreeSet<>(x.top.keySet()); keys.addAll(y.top.keySet());
            for (String k : keys) {
                String va = x.top.get(k), vb = y.top.get(k);
                if (Objects.equals(va, vb)) continue;
                int sev = k.equals("package") ? 2 : (k.endsWith("Sdk") ? 1 : 0);
                add("MANIFEST", sev, k + ": " + va + " -> " + vb, "manifest", "Attribute: " + k + "\nOriginal : " + va + "\nModified : " + vb + "\n");
            }
            keys = new TreeSet<>(x.app.keySet()); keys.addAll(y.app.keySet());
            for (String k : keys) {
                if (k.equals("label") || k.equals("icon") || k.equals("roundIcon") || k.equals("theme")) continue;
                String va = x.app.get(k), vb = y.app.get(k);
                if (Objects.equals(va, vb)) continue;
                boolean appCls = k.equals("name") || k.equals("appComponentFactory");
                int sev = appCls ? 3 : (k.equals("debuggable") ? 2 : 1);
                String why = appCls ? "Application class / factory replaced - a classic injection entry point." : k.equals("networkSecurityConfig") ? "Network security config changed (often used to trust user CAs / allow MITM)." : "";
                add(appCls ? "HOOK" : "MANIFEST", sev, "<application " + k + ">: " + va + " -> " + vb, "manifest", "Attribute: " + k + "\nOriginal : " + va + "\nModified : " + vb + "\n" + why + "\n");
            }
            for (String p : y.perms) if (!x.perms.contains(p)) { pAdd++; addedPerms.add(p); permFinding("+", p); }
            for (String p : x.perms) if (!y.perms.contains(p)) { pRem++; permFinding("-", p); }
            for (String c : y.comps) if (!x.comps.contains(c)) add("COMPONENT", 2, "+ " + c, "added component", "Component added in the modified manifest:\n" + c + "\n");
            for (String c : x.comps) if (!y.comps.contains(c)) {
                boolean prot = Pattern.compile("(?i)pairip|licensecheck|vending|integrity").matcher(c).find();
                add(prot ? "PROTECTION" : "COMPONENT", prot ? 3 : 1, "- " + c, "removed component",
                        "Component removed from the modified manifest:\n" + c + (prot ? "\nThis looks like a Google protection / license component." : "") + "\n");
            }
            for (String f : y.feats) if (!x.feats.contains(f)) add("MANIFEST", 1, "+ " + f, "feature / library", f + " added\n");
            for (String f : x.feats) if (!y.feats.contains(f)) add("MANIFEST", 0, "- " + f, "feature / library", f + " removed\n");
            keys = new TreeSet<>(x.meta.keySet()); keys.addAll(y.meta.keySet());
            for (String k : keys) {
                String va = x.meta.get(k), vb = y.meta.get(k);
                if (Objects.equals(va, vb)) continue;
                add("MANIFEST", 1, "meta-data " + k, va == null ? "added" : vb == null ? "removed" : "changed",
                        "meta-data: " + k + "\nOriginal : " + va + "\nModified : " + vb + "\n");
            }
        } catch (Exception e) { notes.append("Manifest diff failed: ").append(e).append('\n'); }
    }

    private void permFinding(String sign, String p) {
        String info = PERM_INFO.get(p);
        int sev = sign.equals("+") ? (DANGER.contains(p) ? 2 : 1) : (p.contains("BILLING") || p.contains("LICENSE") ? 2 : 0);
        String cat = sign.equals("-") && p.contains("LICENSE") ? "PROTECTION" : "PERMISSION";
        add(cat, sev, sign + " " + p, sign.equals("+") ? "permission added" : "permission removed",
                "Permission: " + p + "\nStatus    : " + (sign.equals("+") ? "ADDED (not in original)" : "REMOVED") + "\n" + (info != null ? info + "\n" : ""));
    }

    // ---------------------------------------------------------------- signature
    private String signer(File apk) {
        try (ZipFile z = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName().toUpperCase(Locale.US);
                if (n.startsWith("META-INF/") && (n.endsWith(".RSA") || n.endsWith(".DSA") || n.endsWith(".EC"))) {
                    try (InputStream in = z.getInputStream(e)) {
                        for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                            if (c instanceof X509Certificate) {
                                X509Certificate x = (X509Certificate) c;
                                byte[] h = MessageDigest.getInstance("SHA-256").digest(x.getEncoded());
                                StringBuilder hx = new StringBuilder();
                                for (byte bb : h) hx.append(String.format("%02X:", bb));
                                return "Subject: " + x.getSubjectX500Principal().getName() + "\nSHA-256: " + hx + "\nValid  : " + x.getNotBefore() + " -> " + x.getNotAfter();
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) { }
        return null;
    }

    private void signatureDiff(File fo, File fm) {
        String a = signer(fo), b = signer(fm);
        if (a == null || b == null) { add("SIGNATURE", 0, "v1 certificate not readable", "v2/v3 only?", "Original: " + a + "\nModified: " + b + "\n"); return; }
        if (a.equals(b)) add("SIGNATURE", 0, "Same signing certificate", "v1", a);
        else add("SIGNATURE", 2, "Signing certificate differs (re-signed)", "v1", "ORIGINAL\n" + a + "\n\nMODIFIED\n" + b + "\n\nThe modified APK is signed with a different key, so Play signature checks / Pairip verification would fail.");
    }

    // ---------------------------------------------------------------- resources.arsc
    private void arscDiff(File fo, File fm) {
        try {
            byte[] a = ZipDiff.entryBytes(fo, "resources.arsc", 150L << 20), b = ZipDiff.entryBytes(fm, "resources.arsc", 150L << 20);
            if (a == null || b == null) return;
            Set<String> sa = new HashSet<>(Arrays.asList(Axml.arscPool(a))), sb = new HashSet<>(Arrays.asList(Axml.arscPool(b)));
            int n = 0;
            for (String s : sb) {
                if (sa.contains(s) || s == null || s.length() < 2 || s.startsWith("res/") || n >= 3000) continue;
                n++;
                add("STRING", 1, "+ \"" + cut(s, 140) + "\"", "resources.arsc (new text resource)", "Text resource added or changed:\n" + s + "\n");
                applyStringRules(s, "resources.arsc", "newString");
            }
            n = 0;
            for (String s : sa) {
                if (sb.contains(s) || s == null || s.length() < 2 || s.startsWith("res/") || n >= 3000) continue;
                n++;
                add("STRING", 0, "- \"" + cut(s, 140) + "\"", "resources.arsc (text removed / replaced)", "Text resource no longer present:\n" + s + "\n");
                applyStringRules(s, "resources.arsc", "removedString");
            }
        } catch (Exception e) { notes.append("arsc diff failed: ").append(e).append('\n'); }
    }

    private void applyStringRules(String s, String where, String scope) {
        for (Rule r : rules)
            if (r.scope.equals(scope) && r.re.matcher(s).find())
                add(r.cat, r.sev, r.label + ": " + cut(s, 120), where, "String : " + s + "\nWhere  : " + where + "\nRule   : " + r.id + "\n");
    }

    private static String cut(String s, int n) { return s.length() > n ? s.substring(0, n) + "..." : s; }

    // ---------------------------------------------------------------- DEX (native)
    private void dexDiff(File fo, File fm, Map<String, ZipDiff.E> A, Map<String, ZipDiff.E> B, File dir) throws Exception {
        List<String> ao = new ArrayList<>(), bo = new ArrayList<>();
        int same = 0;
        for (String n : A.keySet()) if (isDex(n)) { ZipDiff.E b = B.get(n), a = A.get(n); if (b == null || b.crc != a.crc || b.size != a.size) ao.add(n); else same++; }
        for (String n : B.keySet()) if (isDex(n)) { ZipDiff.E a = A.get(n), b = B.get(n); if (a == null || b.crc != a.crc || b.size != a.size) bo.add(n); }
        Comparator<String> byNum = (x, y) -> Integer.compare(dexNum(x), dexNum(y));
        Collections.sort(ao, byNum); Collections.sort(bo, byNum);
        notes.append("DEX: ").append(same).append(" identical file(s) skipped, ").append(ao.size()).append(" original / ").append(bo.size()).append(" modified file(s) analyzed\n");
        if (ao.isEmpty() && bo.isEmpty()) return;
        if (!NativeBridge.ok) { add("INFO", 1, "Native engine not loaded", "DEX analysis skipped", "libdemod.so could not be loaded on this device/ABI."); return; }
        File dO = new File(dir, "dex_o"), dM = new File(dir, "dex_m");
        Util.deleteRec(dO); Util.deleteRec(dM);
        String[] pa = new String[ao.size()], pb = new String[bo.size()];
        int total = ao.size() + bo.size(), k = 0;
        for (int i = 0; i < ao.size(); i++) { File t = new File(dO, ao.get(i)); ZipDiff.extract(fo, ao.get(i), t); pa[i] = t.getPath(); cb.p(46 + (++k) * 10 / Math.max(1, total), "Extracting " + ao.get(i)); }
        for (int i = 0; i < bo.size(); i++) { File t = new File(dM, bo.get(i)); ZipDiff.extract(fm, bo.get(i), t); pb[i] = t.getPath(); cb.p(46 + (++k) * 10 / Math.max(1, total), "Extracting " + bo.get(i)); }
        File rep = new File(dir, "dex.report");
        cb.p(58, "Diffing methods (C++ engine)... this can take a while on large apps");
        int rc = NativeBridge.diffDex(pa, pb, rep.getPath());
        if (rc < 0) { add("INFO", 1, "DEX diff failed (code " + rc + ")", "", "Native engine returned " + rc); return; }
        cb.p(80, "Classifying changes");
        parseReport(rep, bo);
        Util.deleteRec(dO); Util.deleteRec(dM); rep.delete();
    }

    private static boolean isDex(String n) { return n.matches("classes\\d*\\.dex"); }
    private static int dexNum(String n) { String d = n.replaceAll("\\D", ""); return d.isEmpty() ? 1 : Integer.parseInt(d); }

    private static List<String> lines(String s) {
        List<String> r = new ArrayList<>();
        for (String x : s.split("\u001f")) if (!x.isEmpty()) r.add(x);
        return r;
    }

    private static String joinLines(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) sb.append(s).append('\n');
        return sb.toString();
    }

    private static String dexName(List<String> names, String idx) {
        try { int i = Integer.parseInt(idx); if (i >= 0 && i < names.size()) return names.get(i); } catch (Exception ignored) { }
        return "dex#" + idx;
    }

    private static String shortCls(String c) {
        String s = c.startsWith("L") && c.endsWith(";") ? c.substring(1, c.length() - 1) : c;
        return s.substring(s.lastIndexOf('/') + 1);
    }

    private static String shortName(String key) {
        int a = key.indexOf(";->"), p = key.indexOf('(');
        if (a < 0 || p < a) return key;
        return shortCls(key.substring(0, a + 1)) + "." + key.substring(a + 3, p);
    }

    private static String unq(String s) { return s.length() >= 2 && s.startsWith("\"") ? s.substring(1, s.length() - 1) : s; }

    private void collectUses(List<String> ls, String key, Map<String, String> m) {
        if (m.size() > 150000) return;
        for (String s : ls) if (s.startsWith("const-string")) { int sp = s.indexOf(' '); if (sp > 0) m.putIfAbsent(s.substring(sp + 1), key); }
    }

    private void parseReport(File rep, List<String> modDex) throws IOException {
        Set<String> addedCls = new HashSet<>();
        List<String> ca = new ArrayList<>(), cd = new ArrayList<>(), sa = new ArrayList<>(), sd = new ArrayList<>();
        Map<String, List<String>> hookBy = new HashMap<>();
        Map<String, String> useChanged = new HashMap<>(), useAdded = new HashMap<>(), useOld = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(rep), StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = r.readLine()) != null) {
                int t = line.indexOf('\t');
                if (t < 0) continue;
                String k = line.substring(0, t);
                switch (k) {
                    case "CA": ca.add(line.substring(t + 1)); addedCls.add(line.substring(t + 1)); break;
                    case "CD": cd.add(line.substring(t + 1)); break;
                    case "MC": { String[] f = line.split("\t", 5); if (f.length == 5) onChanged(f[1], dexName(modDex, f[2]), f[3], f[4], addedCls, hookBy, useChanged, useOld); break; }
                    case "MA": { String[] f = line.split("\t", 4); if (f.length == 4) onAdded(f[1], dexName(modDex, f[2]), f[3], hookBy, useAdded); break; }
                    case "SA": sa.add(line.substring(t + 1)); break;
                    case "SD": sd.add(line.substring(t + 1)); break;
                    case "CNT": { String[] f = line.split("\t"); for (int i = 1; i < f.length && i <= 7; i++) cnt[i - 1] = Long.parseLong(f[i]); break; }
                    default:
                }
            }
        }
        // strings
        int n = 0;
        for (String s : sa) {
            if (n++ >= 15000) break;
            String raw = unq(s), use = useChanged.get(s) != null ? useChanged.get(s) : useAdded.get(s);
            String det = "String : " + raw + "\nStatus : NEW in modified code\nUsed in: " + (use != null ? use : "(unknown / added library code)") + "\n";
            add("STRING", useChanged.get(s) != null ? 1 : 0, "+ \"" + cut(raw, 140) + "\"", use != null ? "used in " + shortName(use) : "added code string", det);
            applyStringRules(raw, use != null ? use : "dex", "newString");
        }
        n = 0;
        for (String s : sd) {
            if (n++ >= 15000) break;
            String raw = unq(s), use = useOld.get(s);
            add("STRING", use != null ? 1 : 0, "- \"" + cut(raw, 140) + "\"", use != null ? "was used in " + shortName(use) : "removed code string",
                    "String : " + raw + "\nStatus : REMOVED / replaced in modified code\nWas used in: " + (use != null ? use : "(removed or unmodified code)") + "\n");
            applyStringRules(raw, use != null ? use : "dex", "removedString");
        }
        classFindings(ca, cd);
    }

    private String methodDetail(String key, String dexName, String status, String why, String diff, List<String> bl, List<String> al,
                                boolean full, Map<String, List<String>> hookBy) {
        StringBuilder sb = new StringBuilder();
        sb.append("Method : ").append(key).append("\nFile   : ").append(dexName).append("\nStatus : ").append(status)
                .append("\nFlag   : ").append(why).append('\n');
        int a = key.indexOf(';');
        List<String> hk = a > 0 ? hookBy.get(key.substring(0, a + 1)) : null;
        if (hk != null) {
            sb.append("Called from: ");
            for (int i = 0; i < Math.min(5, hk.size()); i++) sb.append(i > 0 ? "; " : "").append(hk.get(i));
            sb.append('\n');
        }
        if (!addedPerms.isEmpty()) {
            sb.append("Manifest permissions added by the mod: ");
            for (int i = 0; i < Math.min(8, addedPerms.size()); i++) sb.append(i > 0 ? ", " : "").append(addedPerms.get(i));
            sb.append('\n');
        }
        sb.append("Note   : pseudo-smali (registers omitted). Heuristic result.\n");
        if (diff != null) sb.append("\n@@DIFF@@\n").append(diff);
        if (full) {
            if (bl != null) sb.append("\n--- ORIGINAL ---\n").append(joinLines(bl));
            if (al != null) sb.append("\n--- MODIFIED ---\n").append(joinLines(al));
        }
        return sb.toString();
    }

    private void onChanged(String key, String dexName, String before, String after, Set<String> addedCls,
                           Map<String, List<String>> hookBy, Map<String, String> useChanged, Map<String, String> useOld) {
        List<String> bl = lines(before), al = lines(after);
        collectUses(bl, key, useOld); collectUses(al, key, useChanged);
        String diff = LineDiff.diff(bl, al, 2);
        boolean flagged = false;
        List<String> eff = new ArrayList<>();
        for (String s : al) if (!s.equals("nop")) eff.add(s);
        boolean prot = KW_PROT.matcher(key).find(), byp = KW_BYP.matcher(key).find(), bool = key.endsWith(")Z");
        String nm = shortName(key);
        if (eff.size() == 2 && eff.get(1).equals("return") && eff.get(0).matches("const/(4|16) -?\\d+")) {
            String c = eff.get(0), v = c.endsWith(" 1") && bool ? "true" : c.endsWith(" 0") && bool ? "false" : c.substring(c.indexOf(' ') + 1);
            if (prot || byp || (bool && bl.size() >= 5) || bl.size() >= 8) {
                String cat = prot ? "PROTECTION" : (byp || bool) ? "BYPASS" : "METHOD";
                add(cat, (prot || byp) ? 3 : (bool ? 2 : 1), "Method forced to return " + v + ": " + nm, key,
                        methodDetail(key, dexName, "CHANGED", "Body replaced by a constant return (" + v + ")", diff, bl, al, true, hookBy));
                flagged = true;
            }
        } else if (eff.size() == 1 && eff.get(0).equals("return-void") && bl.size() >= 6) {
            String cat = prot ? "PROTECTION" : byp ? "BYPASS" : "METHOD";
            add(cat, (prot || byp) ? 3 : 1, "Method emptied (no-op): " + nm, key,
                    methodDetail(key, dexName, "CHANGED", "Body replaced by return-void (check / call disabled)", diff, bl, al, true, hookBy));
            flagged = true;
        }
        String bj = before, aj = after;
        for (Rule r : rules) {
            boolean hit;
            if (r.scope.equals("removedInChanged")) hit = r.re.matcher(bj).find() && !r.re.matcher(aj).find();
            else if (r.scope.equals("addedInChanged")) hit = r.re.matcher(aj).find() && !r.re.matcher(bj).find();
            else continue;
            if (hit) {
                add(r.cat, r.sev, r.label + ": " + nm, key, methodDetail(key, dexName, "CHANGED", r.label + " (rule " + r.id + ")", diff, bl, al, true, hookBy));
                flagged = true;
            }
        }
        Set<String> seen = new HashSet<>();
        for (String s : al) {
            Matcher m = INVOKE.matcher(s);
            if (!m.find()) continue;
            String c = m.group(1);
            if (addedCls.contains(c) && !bj.contains(c + "->") && seen.add(c)) {
                hookBy.computeIfAbsent(c, x -> new ArrayList<>()).add(key);
                if (hookN++ < 400) {
                    add("HOOK", 3, "Injected call to " + shortCls(c) + " from " + nm, key,
                            methodDetail(key, dexName, "CHANGED", "Original method now calls a class that exists only in the modified APK: " + s, diff, bl, al, false, hookBy));
                }
                flagged = true;
            }
        }
        if (!flagged && plain++ < 1500)
            add("METHOD", 1, "Changed: " + nm, key, methodDetail(key, dexName, "CHANGED", "Method body differs", diff, bl, al, false, hookBy));
    }

    private void onAdded(String key, String dexName, String body, Map<String, List<String>> hookBy, Map<String, String> useAdded) {
        if (body.isEmpty()) return;
        List<String> ls = lines(body);
        collectUses(ls, key, useAdded);
        for (Rule r : rules) {
            if (!r.scope.equals("addedMethod") || !r.re.matcher(body).find()) continue;
            if (addedFind++ > 4000) return;
            add(r.cat, r.sev, r.label + ": " + shortName(key), key,
                    methodDetail(key, dexName, "ADDED (not in original)", r.label + " (rule " + r.id + ")", null, null, null, false, hookBy)
                            + "\nKey instructions (invoke / const-string / new-instance):\n" + joinLines(ls));
        }
    }

    private void classFindings(List<String> ca, List<String> cd) {
        for (Rule r : rules) {
            if (!r.scope.equals("addedClass") && !r.scope.equals("removedClass")) continue;
            List<String> src = r.scope.equals("addedClass") ? ca : cd, hits = new ArrayList<>();
            for (String c : src) if (r.re.matcher(c).find()) hits.add(c);
            if (hits.isEmpty()) continue;
            StringBuilder sb = new StringBuilder(r.label + " (" + hits.size() + " classes, rule " + r.id + ")\n\n");
            for (int i = 0; i < Math.min(300, hits.size()); i++) sb.append(hits.get(i)).append('\n');
            add(r.cat, r.sev, r.label + " (" + hits.size() + ")", hits.get(0), sb.toString());
        }
        groups("+", ca); groups("-", cd);
        for (String[] s : SDKS) {
            int a = 0, d = 0;
            for (String c : ca) if (c.startsWith(s[1])) a++;
            for (String c : cd) if (c.startsWith(s[1])) d++;
            if (d > 0) add("SDK", 1, s[0] + " removed (" + d + " classes)", s[1], s[0] + ": " + d + " classes exist in the original but not in the modified APK.\nPackage: " + s[1] + "\n");
            if (a > 0) add("SDK", 1, s[0] + " added (" + a + " classes)", s[1], s[0] + ": " + a + " classes exist only in the modified APK.\nPackage: " + s[1] + "\n");
        }
    }

    private void groups(String sign, List<String> cls) {
        Map<String, List<String>> g = new HashMap<>();
        for (String c : cls) {
            String p = c.length() > 2 ? c.substring(1, c.length() - 1) : c;
            int i = p.lastIndexOf('/');
            p = i < 0 ? "(default)" : p.substring(0, i);
            String[] seg = p.split("/");
            StringBuilder k = new StringBuilder();
            for (int j = 0; j < Math.min(4, seg.length); j++) k.append(j > 0 ? "/" : "").append(seg[j]);
            List<String> l = g.computeIfAbsent(k.toString(), x -> new ArrayList<>());
            l.add(c);
        }
        List<Map.Entry<String, List<String>>> es = new ArrayList<>(g.entrySet());
        Collections.sort(es, (x, y) -> y.getValue().size() - x.getValue().size());
        for (int i = 0; i < Math.min(120, es.size()); i++) {
            Map.Entry<String, List<String>> e = es.get(i);
            StringBuilder sb = new StringBuilder("Package: " + e.getKey().replace('/', '.') + "\nClasses " + (sign.equals("+") ? "ADDED" : "REMOVED") + ": " + e.getValue().size() + "\n\n");
            for (int j = 0; j < Math.min(150, e.getValue().size()); j++) sb.append(e.getValue().get(j)).append('\n');
            add("CLASS", 1, sign + " package " + e.getKey().replace('/', '.') + " (" + e.getValue().size() + ")", e.getValue().size() + " classes", sb.toString());
        }
    }

    // ---------------------------------------------------------------- native libs
    private void nativeDiff(File fo, File fm, Map<String, ZipDiff.E> A, Map<String, ZipDiff.E> B, File dir) {
        if (!NativeBridge.ok) return;
        int n = 0;
        List<String> names = new ArrayList<>(B.keySet());
        Collections.sort(names);
        for (String name : names) {
            if (!name.endsWith(".so")) continue;
            ZipDiff.E a = A.get(name), b = B.get(name);
            if (a != null && a.crc == b.crc && a.size == b.size) continue;
            if (b.size > (80L << 20) || ++n > 12) continue;
            File fa = new File(dir, "so_a.tmp"), fb = new File(dir, "so_b.tmp"), rep = new File(dir, "so.rep");
            try {
                ZipDiff.extract(fm, name, fb);
                if (a != null) ZipDiff.extract(fo, name, fa);
                int rc = NativeBridge.diffStrings(a != null ? fa.getPath() : "", fb.getPath(), rep.getPath(), 6);
                if (rc <= 0) continue;
                int shown = 0;
                try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(rep), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = r.readLine()) != null && shown < 150) {
                        if (!line.startsWith("A\t")) continue;
                        String s = line.substring(2);
                        shown++;
                        add("NATIVE", 0, "+ " + cut(s, 120), name, "New printable string in " + name + (a == null ? " (new library)" : "") + ":\n" + s + "\n");
                        applyStringRules(s, name, "newString");
                        applyStringRules(s, name, "newNativeString");
                    }
                }
            } catch (Exception e) {
                notes.append("native diff ").append(name).append(": ").append(e).append('\n');
            } finally { fa.delete(); fb.delete(); rep.delete(); }
        }
    }
}
