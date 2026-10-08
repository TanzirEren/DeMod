package com.tenix.demod;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

public class DetailActivity extends AppCompatActivity {
    private Finding f;
    private String plain;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_detail);
        final Db db = Db.get(this);
        f = db.get(getIntent().getLongExtra("fid", -1));
        if (f == null) { finish(); return; }
        Util.header(this, Util.catLabel(f.cat) + "  -  " + Util.sevName(f.sev), f.title, true);
        findViewById(R.id.btnAction).setVisibility(View.GONE);
        plain = f.title + "\n" + f.sub + "\n\n" + f.detail.replace("@@DIFF@@", "---- DIFF ( - original / + modified ) ----");
        ((TextView) findViewById(R.id.tvDetail)).setText(colorize(plain));
        findViewById(R.id.btnCopy).setOnClickListener(v -> {
            ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("DeMod", plain));
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
        });
        findViewById(R.id.btnShare).setOnClickListener(v -> startActivity(Intent.createChooser(
                new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, plain), "Share finding")));
        final Button star = findViewById(R.id.btnStar);
        star.setText(f.star ? "Bookmarked" : "Bookmark");
        star.setOnClickListener(v -> {
            f.star = !f.star;
            db.setStar(f.id, f.star);
            star.setText(f.star ? "Bookmarked" : "Bookmark");
        });
    }

    private CharSequence colorize(String s) {
        SpannableStringBuilder sb = new SpannableStringBuilder(s);
        int add = ContextCompat.getColor(this, R.color.diff_add), del = ContextCompat.getColor(this, R.color.diff_del), hunk = ContextCompat.getColor(this, R.color.diff_hunk);
        boolean inDiff = false;
        int pos = 0;
        for (String line : s.split("\n", -1)) {
            int end = pos + line.length();
            if (line.startsWith("---- DIFF")) { inDiff = true; sb.setSpan(new StyleSpan(Typeface.BOLD), pos, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE); }
            else if (line.startsWith("--- ORIGINAL") || line.startsWith("--- MODIFIED")) { inDiff = false; sb.setSpan(new StyleSpan(Typeface.BOLD), pos, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE); }
            else if (inDiff && end > pos) {
                int col = line.startsWith("+ ") ? add : line.startsWith("- ") ? del : line.startsWith("@@") ? hunk : 0;
                if (col != 0) sb.setSpan(new ForegroundColorSpan(col), pos, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            pos = end + 1;
        }
        return sb;
    }
}
