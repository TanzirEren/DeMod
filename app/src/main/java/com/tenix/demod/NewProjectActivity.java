package com.tenix.demod;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

public class NewProjectActivity extends AppCompatActivity {
    private Uri orig, mod;
    private TextView tvOrig, tvMod;
    private EditText etName;

    private final ActivityResultLauncher<String[]> pickOrig = registerForActivityResult(new ActivityResultContracts.OpenDocument(), u -> {
        if (u == null) return;
        keep(u); orig = u;
        tvOrig.setText(Util.nameOf(this, u) + "  (" + Util.size(Util.sizeOf(this, u)) + ")");
    });
    private final ActivityResultLauncher<String[]> pickMod = registerForActivityResult(new ActivityResultContracts.OpenDocument(), u -> {
        if (u == null) return;
        keep(u); mod = u;
        tvMod.setText(Util.nameOf(this, u) + "  (" + Util.size(Util.sizeOf(this, u)) + ")");
    });

    private void keep(Uri u) {
        try { getContentResolver().takePersistableUriPermission(u, Intent.FLAG_GRANT_READ_URI_PERMISSION); } catch (Exception ignored) { }
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_new);
        Util.header(this, "New project", "Pick the original and the modded APK", true);
        findViewById(R.id.btnAction).setVisibility(android.view.View.GONE);
        tvOrig = findViewById(R.id.tvOrig); tvMod = findViewById(R.id.tvMod); etName = findViewById(R.id.etName);
        findViewById(R.id.cardOrig).setOnClickListener(v -> pickOrig.launch(new String[]{"*/*"}));
        findViewById(R.id.cardMod).setOnClickListener(v -> pickMod.launch(new String[]{"*/*"}));
        findViewById(R.id.btnCheck).setOnClickListener(v -> {
            if (orig == null || mod == null) { Toast.makeText(this, "Select both APK files first", Toast.LENGTH_SHORT).show(); return; }
            if (orig.equals(mod)) { Toast.makeText(this, "Original and modified must be different files", Toast.LENGTH_SHORT).show(); return; }
            Project p = new Project();
            String n = etName.getText().toString().trim();
            p.name = n.isEmpty() ? Util.nameOf(this, orig).replaceAll("(?i)\\.apk$", "") : n;
            p.created = System.currentTimeMillis();
            p.origUri = orig.toString(); p.modUri = mod.toString();
            p.origName = Util.nameOf(this, orig); p.modName = Util.nameOf(this, mod);
            p.origSize = Util.sizeOf(this, orig); p.modSize = Util.sizeOf(this, mod);
            long id = Db.get(this).addProject(p);
            ContextCompat.startForegroundService(this, new Intent(this, AnalysisService.class).putExtra("pid", id));
            startActivity(new Intent(this, ResultActivity.class).putExtra("pid", id));
            finish();
        });
    }
}
