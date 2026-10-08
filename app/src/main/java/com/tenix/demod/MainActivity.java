package com.tenix.demod;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.PopupMenu;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.io.*;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private RecyclerView list;
    private TextView empty;
    private final List<Project> data = new ArrayList<>();
    private Adapter ad;

    private final ActivityResultLauncher<String[]> rulePicker = registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
        if (uri == null) return;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            String js = Util.readAll(in);
            new org.json.JSONArray(js); // validate
            try (FileOutputStream o = new FileOutputStream(new File(getFilesDir(), "rules.json"))) { o.write(js.getBytes("UTF-8")); }
            Toast.makeText(this, "Custom rules imported", Toast.LENGTH_SHORT).show();
        } catch (Exception e) { Toast.makeText(this, "Invalid rules.json: " + e.getMessage(), Toast.LENGTH_LONG).show(); }
    });
    private final ActivityResultLauncher<String> notifPerm = registerForActivityResult(new ActivityResultContracts.RequestPermission(), ok -> { });

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        Util.header(this, "DeMod", "APK diff & mod analyzer", false);
        findViewById(R.id.hdrLogo).setVisibility(View.VISIBLE);
        list = findViewById(R.id.list);
        empty = findViewById(R.id.empty);
        ad = new Adapter();
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(ad);
        findViewById(R.id.fab).setOnClickListener(v -> startActivity(new Intent(this, NewProjectActivity.class)));
        ImageButton more = findViewById(R.id.btnAction);
        more.setOnClickListener(v -> {
            PopupMenu m = new PopupMenu(this, v);
            m.getMenu().add(0, 1, 0, "Theme: follow system");
            m.getMenu().add(0, 2, 0, "Theme: light");
            m.getMenu().add(0, 3, 0, "Theme: dark");
            m.getMenu().add(0, 4, 0, "Import custom rules.json");
            m.getMenu().add(0, 5, 0, "Reset rules to default");
            m.getMenu().add(0, 6, 0, "About");
            m.setOnMenuItemClickListener(it -> {
                switch (it.getItemId()) {
                    case 1: setNight(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM); break;
                    case 2: setNight(AppCompatDelegate.MODE_NIGHT_NO); break;
                    case 3: setNight(AppCompatDelegate.MODE_NIGHT_YES); break;
                    case 4: rulePicker.launch(new String[]{"*/*"}); break;
                    case 5: new File(getFilesDir(), "rules.json").delete(); Toast.makeText(this, "Default rules restored", Toast.LENGTH_SHORT).show(); break;
                    default:
                        new MaterialAlertDialogBuilder(this).setTitle("DeMod 1.0")
                                .setMessage("Compare an original APK with a modified one.\nJava UI + C++ DEX engine.\nBrand: TENIx\n\nNative engine: "
                                        + (NativeBridge.ok ? NativeBridge.version() : "not loaded"))
                                .setPositiveButton("OK", null).show();
                }
                return true;
            });
            m.show();
        });
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS);
    }

    private void setNight(int mode) {
        getSharedPreferences("s", 0).edit().putInt("night", mode).apply();
        AppCompatDelegate.setDefaultNightMode(mode);
    }

    @Override protected void onResume() {
        super.onResume();
        data.clear();
        data.addAll(Db.get(this).projects());
        ad.notifyDataSetChanged();
        empty.setVisibility(data.isEmpty() ? View.VISIBLE : View.GONE);
        Util.title(this, "DeMod", data.size() + " project" + (data.size() == 1 ? "" : "s") + " - APK diff & mod analyzer");
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.VH> {
        class VH extends RecyclerView.ViewHolder {
            TextView score, name, info, meta; View del;
            VH(View v) {
                super(v);
                score = v.findViewById(R.id.tvScore); name = v.findViewById(R.id.tvName); info = v.findViewById(R.id.tvInfo);
                meta = v.findViewById(R.id.tvMeta); del = v.findViewById(R.id.btnDel);
            }
        }
        @Override public VH onCreateViewHolder(ViewGroup p, int t) {
            return new VH(getLayoutInflater().inflate(R.layout.item_project, p, false));
        }
        @Override public void onBindViewHolder(VH h, int pos) {
            final Project p = data.get(pos);
            h.name.setText(p.name);
            h.info.setText(p.origName + "  ->  " + p.modName);
            String st = p.status == 2 ? Util.verdict(p.score) : p.status == 1 ? "Analyzing..." : p.status == 3 ? "Failed" : "Not analyzed";
            h.meta.setText(st + "  -  " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(p.created)));
            h.score.setText(p.status == 2 ? String.valueOf(p.score) : "-");
            h.itemView.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, ResultActivity.class).putExtra("pid", p.id)));
            h.del.setOnClickListener(v -> new MaterialAlertDialogBuilder(MainActivity.this).setTitle("Delete project?")
                    .setMessage("This also deletes the stored APK copies and all findings.")
                    .setPositiveButton("Delete", (d, w) -> { Db.get(MainActivity.this).deleteProject(MainActivity.this, p.id); onResume(); })
                    .setNegativeButton("Cancel", null).show());
        }
        @Override public int getItemCount() { return data.size(); }
    }
}
