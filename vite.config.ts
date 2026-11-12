import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Vite's previous default, written out: since Vite 6 the default target is
  // "baseline-widely-available", which would raise the oldest WebKitGTK and
  // Android WebView (minSdk 24) this bundle runs on.
  build: {
    target: ["es2020", "edge88", "firefox78", "chrome87", "safari14"],
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    // Loopback only: the dev server hands out the source tree, so nobody else
    // on the network should reach it.
    //   - desktop dev loads it through devUrl (http://localhost:1420)
    //   - `adb reverse tcp:1420 tcp:1420` (USB-tethered phones, see
    //     scripts/android-dev.ps1) lands on this loopback binding too
    // Tauri sets TAURI_DEV_HOST when Android dev needs another address, such
    // as the LAN IP it picked. Honour it: that keeps the WebView and Vite on
    // the same host string, and it is the only way to bind wider.
    host: host || "127.0.0.1",
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
