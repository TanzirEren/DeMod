package com.tenix.demod;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Minimal binary AndroidManifest.xml (AXML) + resources.arsc string-pool reader. */
final class Axml {
    private Axml() {}

    static final class Manifest {
        final Map<String, String> top = new TreeMap<>();
        final Map<String, String> app = new TreeMap<>();
        final TreeSet<String> perms = new TreeSet<>(), comps = new TreeSet<>(), feats = new TreeSet<>();
        final TreeMap<String, String> meta = new TreeMap<>();
    }

    static int u16(byte[] b, int o) { return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8); }
    static int i32(byte[] b, int o) { return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24); }

    static String[] pool(byte[] b, int c) {
        try {
            int hs = u16(b, c + 2), n = i32(b, c + 8), flags = i32(b, c + 16), ss = i32(b, c + 20);
            boolean utf8 = (flags & 0x100) != 0;
            if (n < 0 || n > 5000000) return new String[0];
            String[] r = new String[n];
            for (int i = 0; i < n; i++) {
                try {
                    int p = c + ss + i32(b, c + hs + 4 * i);
                    if (utf8) {
                        int l = b[p] & 0xff; p++;
                        if ((l & 0x80) != 0) p++;
                        int bl = b[p] & 0xff; p++;
                        if ((bl & 0x80) != 0) { bl = ((bl & 0x7f) << 8) | (b[p] & 0xff); p++; }
                        r[i] = new String(b, p, bl, StandardCharsets.UTF_8);
                    } else {
                        int l = u16(b, p); p += 2;
                        if ((l & 0x8000) != 0) { l = ((l & 0x7fff) << 16) | u16(b, p); p += 2; }
                        r[i] = new String(b, p, l * 2, StandardCharsets.UTF_16LE);
                    }
                } catch (Exception e) { r[i] = ""; }
            }
            return r;
        } catch (Exception e) { return new String[0]; }
    }

    /** Global value string pool of resources.arsc (all text resources). */
    static String[] arscPool(byte[] b) {
        if (b.length < 16 || u16(b, 0) != 2) return new String[0];
        int hs = u16(b, 2);
        if (hs + 8 < b.length && u16(b, hs) == 1) return pool(b, hs);
        return new String[0];
    }

    private static String s(String[] sp, int i) { return i >= 0 && i < sp.length && sp[i] != null ? sp[i] : ""; }

    static Manifest parse(byte[] b) {
        Manifest m = new Manifest();
        String[] sp = new String[0];
        ArrayDeque<String> st = new ArrayDeque<>();
        int pos = 8;
        try {
            while (pos + 8 <= b.length) {
                int type = u16(b, pos), size = i32(b, pos + 4);
                if (size < 8 || pos + size > b.length) break;
                if (type == 1) sp = pool(b, pos);
                else if (type == 0x102) {
                    String tag = s(sp, i32(b, pos + 20));
                    int as = u16(b, pos + 24), ac = u16(b, pos + 28);
                    Map<String, String> at = new HashMap<>();
                    int ap = pos + 16 + as;
                    for (int k = 0; k < ac; k++) {
                        int o = ap + k * 20;
                        if (o + 20 > b.length) break;
                        String nm = s(sp, i32(b, o + 4));
                        int raw = i32(b, o + 8), dt = b[o + 15] & 0xff, data = i32(b, o + 16);
                        String val;
                        switch (dt) {
                            case 3: val = raw >= 0 ? s(sp, raw) : s(sp, data); break;
                            case 0x10: val = String.valueOf(data); break;
                            case 0x11: val = "0x" + Integer.toHexString(data); break;
                            case 0x12: val = data != 0 ? "true" : "false"; break;
                            case 1: val = "@0x" + Integer.toHexString(data); break;
                            default: val = "0x" + Integer.toHexString(data);
                        }
                        at.put(nm, val);
                    }
                    handle(m, tag, at);
                    st.push(tag);
                } else if (type == 0x103) { if (!st.isEmpty()) st.pop(); }
                pos += size;
            }
        } catch (Exception ignored) { }
        return m;
    }

    private static String fix(String n, String pkg) {
        if (n == null) return "";
        if (n.startsWith(".")) return pkg + n;
        if (!n.contains(".") && !pkg.isEmpty()) return pkg + "." + n;
        return n;
    }

    private static void handle(Manifest m, String tag, Map<String, String> at) {
        String pkg = m.top.containsKey("package") ? m.top.get("package") : "";
        String name = at.get("name");
        switch (tag) {
            case "manifest":
                for (String k : new String[]{"package", "versionCode", "versionName"}) if (at.containsKey(k)) m.top.put(k, at.get(k));
                break;
            case "uses-sdk":
                if (at.containsKey("minSdkVersion")) m.top.put("minSdk", at.get("minSdkVersion"));
                if (at.containsKey("targetSdkVersion")) m.top.put("targetSdk", at.get("targetSdkVersion"));
                break;
            case "uses-permission": case "uses-permission-sdk-23": case "permission":
                if (name != null) m.perms.add(name);
                break;
            case "uses-feature": if (name != null) m.feats.add("feature " + name); break;
            case "uses-library": if (name != null) m.feats.add("library " + name); break;
            case "application":
                m.app.putAll(at);
                if (name != null) m.app.put("name", fix(name, pkg));
                break;
            case "activity": case "activity-alias": case "service": case "receiver": case "provider":
                if (name != null) m.comps.add(tag + " " + fix(name, pkg));
                break;
            case "meta-data":
                if (name != null) m.meta.put(name, at.containsKey("value") ? at.get("value") : (at.containsKey("resource") ? at.get("resource") : ""));
                break;
            default:
        }
    }
}
