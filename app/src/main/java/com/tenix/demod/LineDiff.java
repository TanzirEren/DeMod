package com.tenix.demod;

import java.util.*;

/** Small LCS line diff producing "+ line" / "- line" hunks with context. */
final class LineDiff {
    private LineDiff() {}

    static String diff(List<String> a, List<String> b, int ctx) {
        int n = a.size(), m = b.size();
        if ((long) n * m > 360000L) { // fallback for huge bodies
            StringBuilder sb = new StringBuilder("@@ (bodies too large for line diff) @@\n");
            Set<String> sa = new HashSet<>(a), sbb = new HashSet<>(b);
            for (String s : a) if (!sbb.contains(s)) sb.append("- ").append(s).append('\n');
            for (String s : b) if (!sa.contains(s)) sb.append("+ ").append(s).append('\n');
            return sb.toString();
        }
        int[][] L = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--)
            for (int j = m - 1; j >= 0; j--)
                L[i][j] = a.get(i).equals(b.get(j)) ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
        List<String> ops = new ArrayList<>();
        int i = 0, j = 0;
        while (i < n && j < m) {
            if (a.get(i).equals(b.get(j))) { ops.add("  " + a.get(i)); i++; j++; }
            else if (L[i + 1][j] >= L[i][j + 1]) { ops.add("- " + a.get(i)); i++; }
            else { ops.add("+ " + b.get(j)); j++; }
        }
        while (i < n) ops.add("- " + a.get(i++));
        while (j < m) ops.add("+ " + b.get(j++));
        boolean[] show = new boolean[ops.size()];
        for (int k = 0; k < ops.size(); k++)
            if (ops.get(k).charAt(0) != ' ')
                for (int c = Math.max(0, k - ctx); c <= Math.min(ops.size() - 1, k + ctx); c++) show[c] = true;
        StringBuilder sb = new StringBuilder();
        boolean gap = false;
        for (int k = 0; k < ops.size(); k++) {
            if (show[k]) { if (gap) sb.append("@@ ... @@\n"); sb.append(ops.get(k)).append('\n'); gap = false; }
            else gap = true;
        }
        return sb.toString();
    }
}
