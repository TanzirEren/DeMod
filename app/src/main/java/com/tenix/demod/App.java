package com.tenix.demod;

import android.app.Application;
import androidx.appcompat.app.AppCompatDelegate;

public class App extends Application {
    @Override public void onCreate() {
        super.onCreate();
        int m = getSharedPreferences("s", 0).getInt("night", AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM);
        AppCompatDelegate.setDefaultNightMode(m);
    }
}
