# Building Solanum

## Desktop

Requirements: Node 22.12 or newer (releases are built with 26), Rust 1.89 or newer (stable), [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS. No OpenSSL or Perl is needed: the SSH stack is pure Rust.

```bash
git clone https://github.com/joffrey-b/solanum
cd solanum
npm install
npm run tauri dev          # run in development
npm run tauri build        # build release bundle
```

## Android

Extra requirements: Android SDK + Platform-Tools, NDK 27, and JDK 17. `scripts/android-env.ps1` sets `JAVA_HOME`, `ANDROID_HOME`, and `NDK_HOME` for the current PowerShell session; it takes the SDK from `ANDROID_HOME` if that is already set, otherwise from Android Studio's default (`%LOCALAPPDATA%\Android\Sdk`).

```powershell
. .\scripts\android-env.ps1
npm run android:init       # one-time per checkout
npm run android:dev        # build + install on the connected device
npm run android:build      # release APK, unsigned unless a keystore is set up (see below)
```

Device must be plugged in over USB with debugging enabled.

Android refuses to install an unsigned APK. To get a signed one, put a `keystore.properties` file (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`) in `src-tauri/gen/android/`, or set the `SOLANUM_KEYSTORE_PATH`, `SOLANUM_KEYSTORE_PASSWORD`, `SOLANUM_KEY_ALIAS` and `SOLANUM_KEY_PASSWORD` environment variables. `npm run android:dev` needs none of this: it installs a debug build.

Gradle checks every file it downloads against `src-tauri/gen/android/gradle/verification-metadata.xml` and refuses to build on a mismatch. After changing an Android dependency, including a `tauri` or plugin bump, run `node scripts/update-gradle-verification.mjs` and review the diff.

`npm run android:dev` runs `scripts/android-dev.ps1`, which:

1. Verifies `adb` is on PATH and at least one device is listed.
2. Applies `adb reverse tcp:1420 tcp:1420` and `tcp:1421 tcp:1421` (Vite dev + HMR) so the WebView reaches the host via USB loopback.
3. Runs `tauri android dev --host 127.0.0.1` so the WebView's `devUrl` bakes in `127.0.0.1`, matching what `adb reverse` exposes.

This path works whether Wi-Fi is on or off — only USB matters. If you still see `failed request for http://127.0.0.1:1420` while debugging, USB has dropped or the reverse mapping was cleared (re-plug, reboot, or `adb kill-server` all clear it). Re-run `npm run android:dev` and it'll re-apply the mapping. To bypass the helper, use `npm run android:dev:raw` (calls `tauri android dev` directly — Tauri then picks the host's LAN IP).

## Tests and CI

```bash
npm run typecheck                       # TypeScript, no emit
npm run check:versions                  # every manifest names the same version; the Gradle wrapper is pinned
npm run check:licenses                  # THIRD-PARTY-LICENSES.txt matches the lockfiles (after a dependency change: npm run licenses)
npm run build                           # typecheck + production frontend bundle
cd src-tauri && cargo test --locked --lib   # Rust unit tests (vault crypto, profile files, sandbox policy, ...)
```

Every push to `main` and every pull request runs these on GitHub Actions (`.github/workflows/ci.yml`, Linux and Windows) and on GitLab CI (`.gitlab-ci.yml`, which also builds the Linux and Windows installers and an Android APK), along with `cargo clippy`, where the correctness, suspicious and perf lints fail the build. Releases are built from `v*` tags by `.github/workflows/release.yml`, which signs the APK in a job of its own so that no dependency's build step shares a job with the key. All GitHub Actions are pinned to commit SHAs. Linux build dependencies for CI are installed by `scripts/ci-linux-deps.sh`.
