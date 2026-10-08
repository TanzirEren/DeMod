package com.tenix.demod;

/** JNI bridge to the C++ engine (libdemod.so). */
final class NativeBridge {
    static boolean ok;
    static {
        try { System.loadLibrary("demod"); ok = true; } catch (Throwable t) { ok = false; }
    }
    private NativeBridge() {}
    static native int diffDex(String[] orig, String[] mod, String outFile);
    static native int diffStrings(String a, String b, String outFile, int minLen);
    static native String version();
}
