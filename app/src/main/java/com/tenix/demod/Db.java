package com.tenix.demod;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteStatement;
import java.util.*;

final class Db extends SQLiteOpenHelper {
    private static Db inst;

    static synchronized Db get(Context c) {
        if (inst == null) inst = new Db(c.getApplicationContext());
        return inst;
    }

    private Db(Context c) { super(c, "demod.db", null, 1); }

    @Override public void onCreate(SQLiteDatabase d) {
        d.execSQL("CREATE TABLE projects(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,created INTEGER,orig_uri TEXT,mod_uri TEXT,"
                + "orig_name TEXT,mod_name TEXT,orig_size INTEGER,mod_size INTEGER,status INTEGER DEFAULT 0,score INTEGER DEFAULT 0,msg TEXT)");
        d.execSQL("CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT,pid INTEGER,cat TEXT,sev INTEGER,title TEXT,sub TEXT,"
                + "detail TEXT,star INTEGER DEFAULT 0)");
        d.execSQL("CREATE INDEX fidx ON findings(pid,cat)");
    }

    @Override public void onUpgrade(SQLiteDatabase d, int o, int n) { }

    private static final String PCOLS = "id,name,created,orig_uri,mod_uri,orig_name,mod_name,orig_size,mod_size,status,score,msg";

    private static Project proj(Cursor c) {
        Project p = new Project();
        p.id = c.getLong(0); p.name = c.getString(1); p.created = c.getLong(2); p.origUri = c.getString(3);
        p.modUri = c.getString(4); p.origName = c.getString(5); p.modName = c.getString(6); p.origSize = c.getLong(7);
        p.modSize = c.getLong(8); p.status = c.getInt(9); p.score = c.getInt(10); p.msg = c.getString(11);
        return p;
    }

    long addProject(Project p) {
        ContentValues v = new ContentValues();
        v.put("name", p.name); v.put("created", p.created); v.put("orig_uri", p.origUri); v.put("mod_uri", p.modUri);
        v.put("orig_name", p.origName); v.put("mod_name", p.modName); v.put("orig_size", p.origSize);
        v.put("mod_size", p.modSize); v.put("status", 0); v.put("msg", "");
        return getWritableDatabase().insert("projects", null, v);
    }

    List<Project> projects() {
        List<Project> r = new ArrayList<>();
        try (Cursor c = getReadableDatabase().rawQuery("SELECT " + PCOLS + " FROM projects ORDER BY id DESC", null)) {
            while (c.moveToNext()) r.add(proj(c));
        }
        return r;
    }

    Project project(long id) {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT " + PCOLS + " FROM projects WHERE id=?", new String[]{String.valueOf(id)})) {
            return c.moveToFirst() ? proj(c) : null;
        }
    }

    void setStatus(long id, int st, String msg) {
        ContentValues v = new ContentValues();
        v.put("status", st);
        if (msg != null) v.put("msg", msg);
        getWritableDatabase().update("projects", v, "id=?", new String[]{String.valueOf(id)});
    }

    void rename(long id, String name) {
        ContentValues v = new ContentValues();
        v.put("name", name);
        getWritableDatabase().update("projects", v, "id=?", new String[]{String.valueOf(id)});
    }

    void finish(long id, int score, String summary) {
        ContentValues v = new ContentValues();
        v.put("status", 2); v.put("score", score); v.put("msg", summary);
        getWritableDatabase().update("projects", v, "id=?", new String[]{String.valueOf(id)});
    }

    void deleteProject(Context c, long id) {
        SQLiteDatabase d = getWritableDatabase();
        d.delete("findings", "pid=?", new String[]{String.valueOf(id)});
        d.delete("projects", "id=?", new String[]{String.valueOf(id)});
        Util.deleteRec(Util.projDir(c, id));
    }

    void clearFindings(long pid) {
        getWritableDatabase().delete("findings", "pid=?", new String[]{String.valueOf(pid)});
    }

    void insertFindings(long pid, List<Analyzer.F> list) {
        SQLiteDatabase d = getWritableDatabase();
        d.beginTransaction();
        try {
            SQLiteStatement s = d.compileStatement("INSERT INTO findings(pid,cat,sev,title,sub,detail) VALUES(?,?,?,?,?,?)");
            for (Analyzer.F f : list) {
                s.clearBindings();
                s.bindLong(1, pid); s.bindString(2, f.cat); s.bindLong(3, f.sev);
                s.bindString(4, f.title == null ? "" : f.title);
                s.bindString(5, f.sub == null ? "" : f.sub);
                s.bindString(6, f.detail == null ? "" : f.detail);
                s.executeInsert();
            }
            d.setTransactionSuccessful();
        } finally { d.endTransaction(); }
    }

    Map<String, Integer> catCounts(long pid) {
        Map<String, Integer> m = new LinkedHashMap<>();
        try (Cursor c = getReadableDatabase().rawQuery("SELECT cat,COUNT(*) FROM findings WHERE pid=? GROUP BY cat", new String[]{String.valueOf(pid)})) {
            while (c.moveToNext()) m.put(c.getString(0), c.getInt(1));
        }
        return m;
    }

    List<Finding> list(long pid, String cat, String q, boolean star, int minSev) {
        StringBuilder w = new StringBuilder("pid=? AND sev>=?");
        List<String> a = new ArrayList<>();
        a.add(String.valueOf(pid)); a.add(String.valueOf(minSev));
        if (cat != null && !cat.equals("ALL")) { w.append(" AND cat=?"); a.add(cat); }
        if (q != null && q.length() > 0) { w.append(" AND (title LIKE ? OR sub LIKE ?)"); a.add("%" + q + "%"); a.add("%" + q + "%"); }
        if (star) w.append(" AND star=1");
        List<Finding> r = new ArrayList<>();
        try (Cursor c = getReadableDatabase().rawQuery("SELECT id,cat,sev,title,sub,star FROM findings WHERE " + w
                + " ORDER BY sev DESC,id LIMIT 4000", a.toArray(new String[0]))) {
            while (c.moveToNext()) {
                Finding f = new Finding();
                f.id = c.getLong(0); f.cat = c.getString(1); f.sev = c.getInt(2); f.title = c.getString(3);
                f.sub = c.getString(4); f.star = c.getInt(5) == 1;
                r.add(f);
            }
        }
        return r;
    }

    Finding get(long id) {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT id,cat,sev,title,sub,detail,star FROM findings WHERE id=?", new String[]{String.valueOf(id)})) {
            if (!c.moveToFirst()) return null;
            Finding f = new Finding();
            f.id = c.getLong(0); f.cat = c.getString(1); f.sev = c.getInt(2); f.title = c.getString(3);
            f.sub = c.getString(4); f.detail = c.getString(5); f.star = c.getInt(6) == 1;
            return f;
        }
    }

    void setStar(long id, boolean s) {
        ContentValues v = new ContentValues();
        v.put("star", s ? 1 : 0);
        getWritableDatabase().update("findings", v, "id=?", new String[]{String.valueOf(id)});
    }

    /** Streaming cursor for exports: id,cat,sev,title,sub,detail,star. */
    Cursor all(long pid) {
        return getReadableDatabase().rawQuery("SELECT id,cat,sev,title,sub,detail,star FROM findings WHERE pid=? ORDER BY cat,sev DESC,id",
                new String[]{String.valueOf(pid)});
    }
}
