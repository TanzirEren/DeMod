package com.tenix.demod;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Reads only the ZIP central directory (CRC/size) - instant even for 500 MB+ APKs. */
final class ZipDiff {
    static final class E { long crc, size, csize; }

    private ZipDiff() {}

    static Map<String, E> read(File f) throws IOException {
        Map<String, E> m = new LinkedHashMap<>();
        try (ZipFile z = new ZipFile(f)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                E x = new E();
                x.crc = e.getCrc(); x.size = e.getSize(); x.csize = e.getCompressedSize();
                m.put(e.getName(), x);
            }
        }
        return m;
    }

    static byte[] entryBytes(File f, String name, long maxBytes) throws IOException {
        try (ZipFile z = new ZipFile(f)) {
            ZipEntry e = z.getEntry(name);
            if (e == null) return null;
            if (e.getSize() > maxBytes) return null;
            try (InputStream in = z.getInputStream(e)) {
                ByteArrayOutputStream bo = new ByteArrayOutputStream((int) Math.max(1024, e.getSize()));
                byte[] buf = new byte[65536]; int n;
                while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
                return bo.toByteArray();
            }
        }
    }

    static void extract(File f, String name, File out) throws IOException {
        File p = out.getParentFile();
        if (p != null) p.mkdirs();
        try (ZipFile z = new ZipFile(f)) {
            ZipEntry e = z.getEntry(name);
            if (e == null) throw new FileNotFoundException(name);
            try (InputStream in = z.getInputStream(e); OutputStream o = new BufferedOutputStream(new FileOutputStream(out), 1 << 16)) {
                byte[] buf = new byte[1 << 16]; int n;
                while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            }
        }
    }
}
