# DeMod  (by TENIx)

Android app that compares an **original APK** with a **modified APK** and explains what the modder changed.
Java UI (Material 3) + C++ DEX engine (JNI). Built with GitHub Actions - no local SDK needed.

## Build with GitHub
1. Create a new GitHub repo, upload everything in this folder (keep `.github/workflows/build.yml`).
2. Open **Actions -> Build DeMod -> Run workflow** (it also runs on every push).
3. Download `DeMod-debug-apk` or `DeMod-release-apk` from the run's **Artifacts**.
   (Release is signed with the debug key so it installs directly.)

The workflow installs JDK 17, Android SDK 34, NDK 26.1, CMake 3.22 and Gradle 8.5 itself,
so the Gradle wrapper jar is not required.

## How analysis works (handles 500 MB+ APKs)
1. ZIP central directory compare (CRC/size) -> added / removed / modified files in seconds.
2. Only DEX files whose CRC changed are extracted and handed to the C++ engine (mmap, multithreaded).
3. C++ parses DEX, builds a normalized pseudo-smali fingerprint for every method (registers omitted),
   and reports added/removed classes, changed methods, new/removed code strings.
4. Java classifies results with `assets/rules.json` + built-in heuristics:
   Pairip/Google protection, bypass (forced-true methods, billing, premium flags), strings, dialogs, toasts,
   hooks (original code calling classes that exist only in the mod), permissions, components, manifest,
   signature, native libs (string diff), URLs/domains, ad/analytics SDKs, added packages.
5. Results go to SQLite; UI pages them (search, category chips, severity filter, bookmarks).

## Features
Project list, history, rename/delete, foreground-service analysis with progress, mod-impact score,
category chips + counts, search, severity filter, bookmarks, diff viewer (red/green), copy/share finding,
copy whole tab, custom rules import (rules.json), dark/light/system theme,
export: TXT, Markdown, HTML, JSON, CSV, method patch (.diff), full ZIP bundle (reports + added/changed files).

## Honest limits
* Detection is heuristic (pattern based) - always verify in the shown pseudo-smali.
* Pseudo-smali is a readable summary, not assemblable smali.
* Runtime hooks (Frida/Xposed) cannot be found statically; only code injected into the APK.
* Only the v1 (META-INF) signing certificate is compared.
* Needs free storage for two copies of the APKs.

Edit `app/src/main/assets/rules.json` to add new protection/bypass patterns without touching Java.
