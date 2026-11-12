//! Android: the Kotlin side of the app, reached through a plugin of its own
//! (`gen/android/app/src/main/java/io/github/joffrey_b/solanum/`).
//! `KeepAlivePlugin` runs the foreground service that keeps the process, and
//! so every SSH session in it, alive while Solanum is in the background and
//! the window has a session open (F-004, F-032, F-033), holds the
//! screen-privacy setting (`FLAG_SECURE`), and shows the system's file screens
//! for importing and exporting a profile.
//!
//! The plugin has no Rust commands, so it adds nothing to what the webview may
//! call; the Kotlin commands are reached only from here. Its state (a
//! `PluginHandle`, which owns an `AppHandle`) exists only on Android and never
//! in `SshState`.

/// The number of SSH session tabs the window has open. On Android the
/// keep-alive service runs while it is above 0; elsewhere nothing happens.
#[tauri::command]
pub async fn android_keep_alive(app: tauri::AppHandle, sessions: u32) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        kotlin::call::<()>(&app, "setSessions", serde_json::json!({ "count": sessions })).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, sessions);
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
const ANDROID_ONLY: &str = "Only on Android.";

/// Settings > "Hide Solanum from screenshots and Recents": whether the window
/// carries Android's `FLAG_SECURE` (screenshots, screen recordings, casting
/// and the Recents preview show it blank). On by default; the Kotlin side
/// keeps it, so that it applies before the first frame.
#[tauri::command]
pub async fn android_screen_privacy(app: tauri::AppHandle) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        #[derive(serde::Deserialize)]
        struct State {
            on: bool,
        }
        kotlin::call::<State>(&app, "getScreenPrivacy", serde_json::json!({})).await.map(|s| s.on)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err(ANDROID_ONLY.into())
    }
}

/// Turns the setting above on or off; the window changes at once.
#[tauri::command]
pub async fn android_set_screen_privacy(app: tauri::AppHandle, on: bool) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        kotlin::call::<()>(&app, "setScreenPrivacy", serde_json::json!({ "on": on })).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, on);
        Err(ANDROID_ONLY.into())
    }
}

#[cfg(target_os = "android")]
pub(crate) use kotlin::plugin;

/// The private copy the picker made of the document the user chose, until the
/// import has used it. Remembered here so only that file is ever deleted.
#[cfg(target_os = "android")]
static STAGED_IMPORT: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// A document chosen in the system's file picker, copied to a private file.
#[cfg(target_os = "android")]
pub(crate) struct PickedProfile {
    pub(crate) path: String,
    /// What the document provider calls it. Untrusted.
    pub(crate) name: Option<String>,
}

/// Shows the system's file picker. `None` if the user backed out. Waits for
/// the user for as long as it takes. The copy stops at `max_bytes`.
#[cfg(target_os = "android")]
pub(crate) async fn pick_profile_file(
    app: &tauri::AppHandle,
    max_bytes: u64,
) -> Result<Option<PickedProfile>, String> {
    #[derive(serde::Deserialize)]
    struct Answer {
        path: Option<String>,
        name: Option<String>,
    }
    let answer: Answer =
        kotlin::call(app, "pickProfileFile", serde_json::json!({ "maxBytes": max_bytes })).await?;
    let Some(path) = answer.path else { return Ok(None) };
    *STAGED_IMPORT.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::path::PathBuf::from(&path));
    Ok(Some(PickedProfile { path, name: answer.name }))
}

/// Shows the system's "Save as" screen and copies the profile's file to the
/// document the user creates. Returns that document's name, `None` if the user
/// backed out. Waits for the user for as long as it takes.
#[cfg(target_os = "android")]
pub(crate) async fn save_profile_file(
    app: &tauri::AppHandle,
    source: &std::path::Path,
    suggested_name: &str,
) -> Result<Option<String>, String> {
    #[derive(serde::Deserialize)]
    struct Answer {
        name: Option<String>,
    }
    let answer: Answer = kotlin::call(
        app,
        "saveProfileFile",
        serde_json::json!({ "path": source.to_string_lossy(), "name": suggested_name }),
    )
    .await?;
    Ok(answer.name)
}

/// Deletes the private copy, once the import is done or the file is refused.
#[cfg(target_os = "android")]
pub(crate) fn discard_staged_import() {
    if let Some(path) = STAGED_IMPORT.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(target_os = "android")]
mod kotlin {
    use serde::de::DeserializeOwned;
    use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
    use tauri::{Manager, Runtime};

    struct Kotlin<R: Runtime>(PluginHandle<R>);

    /// Registers `KeepAlivePlugin`. Without it Solanum still runs, without
    /// the keep-alive: the window logs the command's refusal.
    pub(crate) fn plugin<R: Runtime>() -> TauriPlugin<R> {
        Builder::new("solanum-android")
            .setup(|app, api| {
                match api.register_android_plugin("io.github.joffrey_b.solanum", "KeepAlivePlugin") {
                    Ok(handle) => {
                        app.manage(Kotlin(handle));
                    }
                    Err(e) => eprintln!("Solanum: the Android keep-alive is not available: {e}"),
                }
                Ok(())
            })
            .build()
    }

    pub(super) async fn call<T: DeserializeOwned>(
        app: &tauri::AppHandle,
        command: &str,
        payload: serde_json::Value,
    ) -> Result<T, String> {
        let kotlin = app
            .try_state::<Kotlin<tauri::Wry>>()
            .ok_or("The Android side of Solanum did not load.")?;
        kotlin.0.run_mobile_plugin_async(command, payload).await.map_err(|e| e.to_string())
    }
}
