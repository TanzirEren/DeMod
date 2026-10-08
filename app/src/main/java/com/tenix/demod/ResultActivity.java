package com.tenix.demod;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.PopupMenu;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ResultActivity extends AppCompatActivity implements AnalysisService.Listener {
    private long pid;
    private Db db;
    private Project proj;
    private String selCat = "ALL", query = "";
    private boolean starOnly;
    private int minSev;
    private List<Finding> data = new ArrayList<>();
    private Adapter ad;
    private View progressBox, content;
    private TextView tvStage, tvPct, tvScore, tvVerdict, tvSummary, tvCount;
    private LinearProgressIndicator bar;
    private MaterialButton retry;
    private ChipGroup chips;
    private final Handler h = new Handler(Looper.getMainLooper());
    private Runnable pending;
    private int startWait;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_result);
        pid = getIntent().getLongExtra("pid", -1);
        db = Db.get(this);
        Util.header(this, "Result", "", true);
        progressBox = findViewById(R.id.progressBox); content = findViewById(R.id.content);
        tvStage = findViewById(R.id.tvStage); tvPct = findViewById(R.id.tvPct); bar = findViewById(R.id.bar);
        retry = findViewById(R.id.btnRetry); tvScore = findViewById(R.id.tvScore); tvVerdict = findViewById(R.id.tvVerdict);
        tvSummary = findViewById(R.id.tvSummary); tvCount = findViewById(R.id.tvCount); chips = findViewById(R.id.chips);
        RecyclerView list = findViewById(R.id.list);
        ad = new Adapter();
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(ad);
        retry.setOnClickListener(v -> {
            androidx.core.content.ContextCompat.startForegroundService(this, new Intent(this, AnalysisService.class).putExtra("pid", pid));
            showProgress(0, "Restarting...", false);
        });
        EditText et = findViewById(R.id.etSearch);
        et.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int c, int d) { }
            @Override public void onTextChanged(CharSequence s, int a, int c, int d) { }
            @Override public void afterTextChanged(Editable s) {
                query = s.toString().trim();
                if (pending != null) h.removeCallbacks(pending);
                pending = ResultActivity.this::load;
                h.postDelayed(pending, 250);
            }
        });
        findViewById(R.id.btnAction).setOnClickListener(this::menu);
    }

    @Override protected void onStart() {
        super.onStart();
        AnalysisService.listener = this;
        refresh();
    }

    @Override protected void onStop() {
        super.onStop();
        if (AnalysisService.listener == this) AnalysisService.listener = null;
    }

    @Override public void onProgress(long p, int pct, String msg) { if (p == pid) showProgress(pct, msg, false); }
    @Override public void onDone(long p) { if (p == pid) refresh(); }

    private void showProgress(int pct, String msg, boolean failed) {
        progressBox.setVisibility(View.VISIBLE); content.setVisibility(View.GONE);
        tvStage.setText(msg);
        bar.setVisibility(failed ? View.GONE : View.VISIBLE);
        tvPct.setText(failed ? "" : pct + "%");
        bar.setProgressCompat(pct, true);
        retry.setVisibility(failed ? View.VISIBLE : View.GONE);
    }

    private void refresh() {
        proj = db.project(pid);
        if (proj == null) { finish(); return; }
        Util.title(this, proj.name, proj.origName + "  ->  " + proj.modName);
        if (proj.status == 1 && AnalysisService.running == pid) { showProgress(AnalysisService.pct, AnalysisService.msg, false); return; }
        if (proj.status == 3) { showProgress(0, "Analysis failed:\n" + proj.msg, true); return; }
        if (proj.status == 0 && (AnalysisService.running == pid || startWait++ < 6)) {
            showProgress(AnalysisService.pct, "Starting...", false);
            h.postDelayed(this::refresh, 600);
            return;
        }
        if (proj.status != 2) { showProgress(0, "Analysis did not finish (the app was closed or killed).", true); return; }
        progressBox.setVisibility(View.GONE); content.setVisibility(View.VISIBLE);
        tvScore.setText(String.valueOf(proj.score));
        tvVerdict.setText(Util.verdict(proj.score) + "  (mod impact " + proj.score + "/100)");
        tvSummary.setText(proj.msg);
        buildChips();
        load();
    }

    private void buildChips() {
        chips.removeAllViews();
        Map<String, Integer> cc = db.catCounts(pid);
        int total = 0;
        for (int v : cc.values()) total += v;
        addChip("ALL", "All", total);
        for (String c : Util.CATS) if (cc.containsKey(c)) addChip(c, Util.catLabel(c), cc.get(c));
    }

    private void addChip(final String cat, String label, int n) {
        Chip c = new Chip(this);
        c.setText(label + "  " + n);
        c.setCheckable(true);
        c.setChecked(cat.equals(selCat));
        c.setOnClickListener(v -> { selCat = cat; load(); });
        chips.addView(c);
    }

    private void load() {
        data = db.list(pid, selCat, query, starOnly, minSev);
        ad.notifyDataSetChanged();
        tvCount.setText(data.size() + (data.size() >= 4000 ? "+ findings (refine your search)" : " findings") + (starOnly ? "  -  bookmarks only" : "") + (minSev > 0 ? "  -  " + Util.sevName(minSev) + "+" : ""));
    }

    private void menu(View anchor) {
        PopupMenu m = new PopupMenu(this, anchor);
        m.getMenu().add(0, 1, 0, "Export report...");
        m.getMenu().add(0, 2, 0, "Copy this tab (text)");
        m.getMenu().add(0, 3, 0, starOnly ? "Show all findings" : "Show bookmarks only");
        m.getMenu().add(0, 4, 0, "Minimum severity...");
        m.getMenu().add(0, 5, 0, "Rename project");
        m.getMenu().add(0, 6, 0, "Run analysis again");
        m.setOnMenuItemClickListener(it -> {
            switch (it.getItemId()) {
                case 1: exportDialog(); break;
                case 2: copyTab(); break;
                case 3: starOnly = !starOnly; load(); break;
                case 4:
                    new MaterialAlertDialogBuilder(this).setTitle("Minimum severity")
                            .setItems(new String[]{"All", "Low and above", "Medium and above", "High only"}, (d, w) -> { minSev = w; load(); }).show();
                    break;
                case 5: rename(); break;
                default:
                    ContextCompat.startForegroundService(this, new Intent(this, AnalysisService.class).putExtra("pid", pid));
                    showProgress(0, "Restarting...", false);
            }
            return true;
        });
        m.show();
    }

    private void rename() {
        final EditText et = new EditText(this);
        et.setText(proj.name);
        new MaterialAlertDialogBuilder(this).setTitle("Rename project").setView(et)
                .setPositiveButton("Save", (d, w) -> { String n = et.getText().toString().trim(); if (!n.isEmpty()) { db.rename(pid, n); refresh(); } })
                .setNegativeButton("Cancel", null).show();
    }

    private void copyTab() {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Finding f : data) {
            if (sb.length() > 150000 || n++ > 400) break;
            Finding full = db.get(f.id);
            sb.append("[").append(Util.sevName(f.sev)).append("] ").append(f.title).append('\n').append(f.sub).append('\n')
                    .append(full.detail.replace("@@DIFF@@", "---- DIFF ----")).append("\n\n");
        }
        ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("DeMod", sb.toString()));
        Toast.makeText(this, "Copied " + Math.min(n, data.size()) + " findings", Toast.LENGTH_SHORT).show();
    }

    private void exportDialog() {
        new MaterialAlertDialogBuilder(this).setTitle("Export").setItems(Exporter.FORMATS, (d, w) -> {
            Toast.makeText(this, "Exporting...", Toast.LENGTH_SHORT).show();
            new Thread(() -> {
                try {
                    final File f = Exporter.export(this, proj, w);
                    runOnUiThread(() -> {
                        Toast.makeText(this, "Saved: " + f.getAbsolutePath(), Toast.LENGTH_LONG).show();
                        Exporter.share(this, f);
                    });
                } catch (Throwable e) {
                    runOnUiThread(() -> Toast.makeText(this, "Export failed: " + e, Toast.LENGTH_LONG).show());
                }
            }, "demod-export").start();
        }).show();
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.VH> {
        class VH extends RecyclerView.ViewHolder {
            View bar; TextView cat, title, sub; ImageView star;
            VH(View v) {
                super(v);
                bar = v.findViewById(R.id.sevBar); cat = v.findViewById(R.id.tvCat); title = v.findViewById(R.id.tvTitle);
                sub = v.findViewById(R.id.tvSub); star = v.findViewById(R.id.ivStar);
            }
        }
        @Override public VH onCreateViewHolder(ViewGroup p, int t) { return new VH(getLayoutInflater().inflate(R.layout.item_finding, p, false)); }
        @Override public void onBindViewHolder(VH v, int pos) {
            final Finding f = data.get(pos);
            int col = Util.sevColor(ResultActivity.this, f.sev);
            v.bar.setBackgroundColor(col);
            v.cat.setTextColor(col);
            v.cat.setText((Util.catLabel(f.cat) + "  -  " + Util.sevName(f.sev)).toUpperCase());
            v.title.setText(f.title);
            v.sub.setText(f.sub);
            v.star.setImageResource(f.star ? R.drawable.ic_star : R.drawable.ic_star_outline);
            v.star.setOnClickListener(x -> { f.star = !f.star; db.setStar(f.id, f.star); notifyItemChanged(v.getAdapterPosition()); });
            v.itemView.setOnClickListener(x -> startActivity(new Intent(ResultActivity.this, DetailActivity.class).putExtra("fid", f.id)));
        }
        @Override public int getItemCount() { return data.size(); }
    }
}
