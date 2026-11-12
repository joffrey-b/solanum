import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./App.css";

// Bundled terminal fonts (regular + bold only — no italic, xterm's own text
// attributes don't need it here). The latin-only subset of each: SSH
// sessions in this app are Latin-script text, and each package's plain
// "400.css" bundles every script subset it ships (cyrillic, greek, hebrew,
// arabic, vietnamese, braille, symbols2...), which Vite's build then copies
// into the app bundle in full since it's static-asset bundling, not a
// browser lazy-loading unicode-range at runtime — needlessly inflating
// install size for glyphs this app never renders. Imported once, globally,
// rather than per-component, so both the live terminal and the Settings
// font picker's own preview always have the same fonts available regardless
// of load order. See src/util/terminalFonts.ts for the matching
// font-family list.
//
// Each of these CSS files' @font-face rules still lists a .woff fallback
// after the .woff2 src, unused by any of this app's Tauri targets (desktop
// WebKit/WebView2 and Android WebView all support woff2 natively) — a few
// hundred KB of dead weight per font. Left as-is rather than hand-stripping
// it: doing that reliably would mean depending on @fontsource's internal,
// non-public file layout, which is more fragile than the bytes it'd save.
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "@fontsource/fira-code/latin-400.css";
import "@fontsource/fira-code/latin-700.css";
import "@fontsource/cascadia-code/latin-400.css";
import "@fontsource/cascadia-code/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-700.css";
import "@fontsource/source-code-pro/latin-400.css";
import "@fontsource/source-code-pro/latin-700.css";

// Last-resort global handlers so a failure that escapes React (an async reject,
// a listener throw) is at least recorded instead of vanishing silently. The
// ErrorBoundary below covers render-time throws; these cover everything else.
window.addEventListener("unhandledrejection", (e) => {
  console.error("[app] unhandled promise rejection:", e.reason);
});
window.addEventListener("error", (e) => {
  console.error("[app] uncaught error:", e.error ?? e.message);
});

// ── Android soft-keyboard sizing (visualViewport → --vv-h) ──────────────────
// The Android on-screen keyboard covers our fixed-bottom UI (MobileKeyBar,
// Sidebar dock) unless the layout root shrinks with the keyboard. The
// AndroidManifest sets `windowSoftInputMode="adjustResize"` which shrinks
// the Activity window on every OS version we support — but on older
// WebViews (pre-Chromium M139, mid-2025) `100vh` occasionally lags a frame
// behind the resize. Belt-and-braces: mirror `window.visualViewport.height`
// into a `--vv-h` CSS variable that `#root` reads (see index.html). On
// desktop the value equals `innerHeight` and never changes, so there's zero
// runtime cost.
//
// Fires on:
//   - visualViewport.resize   → keyboard open/close, pinch-zoom
//   - visualViewport.scroll   → URL bar collapse / IME partial slide
//   - window.resize           → window resize (desktop)
//   - window.orientationchange → device rotation (kb usually re-computes)
function syncVvHeight() {
  const vv = window.visualViewport;
  const h = vv ? vv.height : window.innerHeight;
  document.documentElement.style.setProperty("--vv-h", `${h}px`);
}
syncVvHeight();
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", syncVvHeight);
  window.visualViewport.addEventListener("scroll", syncVvHeight);
}
window.addEventListener("resize", syncVvHeight);
window.addEventListener("orientationchange", syncVvHeight);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
