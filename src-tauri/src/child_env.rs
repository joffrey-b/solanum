//! The environment of the programs Solanum starts (F-014).
//!
//! On Linux `run()` sets a few variables for Solanum's own window: WebKit's
//! GPU workarounds and sandbox switch, `GDK_BACKEND`, `LIBGL_ALWAYS_SOFTWARE`.
//! They have to be in the process environment, because GTK reads them here and
//! WebKit's web process inherits them when WebKit starts it. A local shell, an
//! editor or a browser Solanum starts should get the user's environment
//! instead: forced software rendering or XWayland, or a disabled WebKit
//! sandbox, would carry over into them. Only variables the user had not set
//! are ever set, so giving a child the user's environment means removing them
//! from its command.
//!
//! The AppImage adds a second layer before Solanum even starts (N-016): its
//! `AppRun` puts the image's folders first in `LD_LIBRARY_PATH`, `PATH` and
//! others, and sets `PYTHONHOME` into the image; its GTK hook sets the GTK
//! module paths, the theme and `GDK_BACKEND`. Solanum needs them, a local shell
//! does not: its programs would load the image's libraries. `undo_appimage`
//! works out how to take them back out.

#[cfg(not(target_os = "android"))]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(not(target_os = "android"))]
use std::sync::OnceLock;

/// How the environment of a program Solanum starts differs from Solanum's own.
#[cfg(not(target_os = "android"))]
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ChildEnv {
    remove: Vec<OsString>,
    set: Vec<(OsString, OsString)>,
    /// Where a launched program starts, if not where Solanum is. Not for a
    /// terminal: portable-pty starts it in the folder asked for, or at home.
    cwd: Option<OsString>,
}

/// Worked out once, by `set_for_app_only`.
#[cfg(not(target_os = "android"))]
static FOR_CHILDREN: OnceLock<ChildEnv> = OnceLock::new();

/// Set `vars` in this process's environment and work out what its children
/// must not inherit: those, and what an AppImage's scripts changed. Call once,
/// first thing in `run()`, before any thread starts.
#[cfg(target_os = "linux")]
pub(crate) fn set_for_app_only(vars: &[(&'static str, &'static str)]) {
    let mut children = undo_appimage(&std::env::vars_os().collect::<Vec<_>>());
    children.remove.extend(vars.iter().map(|(name, _)| OsString::from(name)));
    for (name, value) in vars {
        std::env::set_var(name, value);
    }
    let _ = FOR_CHILDREN.set(children);
}

/// What every program Solanum starts must not inherit.
#[cfg(not(target_os = "android"))]
pub(crate) fn for_children() -> &'static ChildEnv {
    FOR_CHILDREN.get_or_init(ChildEnv::default)
}

/// Values an AppImage's scripts set that are not paths into the image, or that
/// say which image this is: nothing a child should see. The user's own value
/// of one of these was overwritten before Solanum started, and cannot be
/// brought back.
#[cfg(target_os = "linux")]
const APPIMAGE_ONLY: &[&str] = &["APPDIR", "APPIMAGE", "ARGV0", "OWD", "GDK_BACKEND", "GTK_THEME", "PYTHONDONTWRITEBYTECODE"];

/// Given the environment of a process started by an AppImage: the changes that
/// give its children the environment from before the AppImage. Elsewhere,
/// nothing.
///
/// This reads what is in the environment, not a list of variables the scripts
/// are known to change: any entry inside the image goes, whichever variable it
/// is in, so a new version of those scripts does not bring the problem back.
#[cfg(target_os = "linux")]
fn undo_appimage(env: &[(OsString, OsString)]) -> ChildEnv {
    let get = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let (Some(_), Some(appdir)) = (get("APPIMAGE"), get("APPDIR")) else {
        return ChildEnv::default();
    };
    let appdir = appdir.as_bytes();
    let appdir = appdir.strip_suffix(b"/").unwrap_or(appdir);
    if appdir.is_empty() {
        return ChildEnv::default();
    }
    let inside = |entry: &[u8]| entry.strip_prefix(appdir).is_some_and(|rest| rest.is_empty() || rest[0] == b'/');

    let mut changes = ChildEnv { remove: APPIMAGE_ONLY.iter().map(OsString::from).collect(), set: Vec::new(), cwd: None };
    for (name, value) in env {
        if changes.remove.contains(name) {
            continue;
        }
        let entries = value.as_bytes().split(|b| *b == b':');
        if !entries.clone().any(inside) {
            continue;
        }
        // Empty entries go too. AppRun leaves one at the end of a variable that
        // was not set, and in LD_LIBRARY_PATH or PATH it means the current
        // folder.
        let mut kept: Vec<&[u8]> = entries.filter(|e| !e.is_empty() && !inside(e)).collect();
        // The GTK hook also adds a bare /usr/share in front of the user's list.
        if name == "XDG_DATA_DIRS" && kept.first() == Some(&&b"/usr/share"[..]) {
            kept.remove(0);
        }
        if kept.is_empty() {
            changes.remove.push(name.clone());
        } else {
            changes.set.push((name.clone(), OsString::from_vec(kept.join(&b':'))));
        }
    }
    // AppRun also changes folder, into the image. A program opened from there
    // would keep the mount busy and sit in a dead folder once Solanum quits.
    // OWD is the folder it was started in; extract-and-run does not set it.
    changes.cwd = [get("OWD"), get("HOME")]
        .into_iter()
        .flatten()
        .find(|dir| !dir.is_empty() && !inside(dir.as_bytes()))
        .cloned();
    changes
}

/// Workarounds that keep the window from aborting or staying blank on some
/// Linux graphics stacks, given the current environment (`env`). A variable
/// the user set is left as it is, so anyone can opt back in (or out).
///
/// - `WEBKIT_DISABLE_HARDWARE_ACCELERATION`, `WEBKIT_DISABLE_DMABUF_RENDERER`,
///   `WEBKIT_DISABLE_COMPOSITING_MODE`, `LIBGL_ALWAYS_SOFTWARE`: the DMA-BUF +
///   EGL renderer WebKit defaults to aborts with `EGL_BAD_PARAMETER` on
///   Mesa 24 and later on many GPUs (WebKit #258834, tauri-apps/tauri#9304).
///   The abort happens inside WebKit's web process, so it cannot be detected
///   before WebKit starts; these are always set. They cost Solanum's window
///   GPU rendering, which a terminal and file lists do not need.
/// - `GDK_BACKEND=x11`: on Wayland with Mesa 24 and later the bundled
///   webkit2gtk-4.1 still aborts in `eglGetDisplay()` against a `wl_display`
///   (its libwayland-egl predates the host Mesa); going through XWayland avoids
///   that handshake. Set only on a Wayland session that has XWayland
///   (`DISPLAY`): on X11 it changes nothing, and without XWayland GTK could not
///   open a display at all.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn graphics_workarounds(env: impl Fn(&str) -> Option<OsString>) -> Vec<(&'static str, &'static str)> {
    let mut vars = Vec::new();
    for name in [
        "WEBKIT_DISABLE_HARDWARE_ACCELERATION",
        "WEBKIT_DISABLE_DMABUF_RENDERER",
        "WEBKIT_DISABLE_COMPOSITING_MODE",
        "LIBGL_ALWAYS_SOFTWARE",
    ] {
        if env(name).is_none() {
            vars.push((name, "1"));
        }
    }
    let present = |name: &str| env(name).is_some_and(|v| !v.is_empty());
    let wayland = present("WAYLAND_DISPLAY") || env("XDG_SESSION_TYPE").is_some_and(|v| v == "wayland");
    if env("GDK_BACKEND").is_none() && wayland && present("DISPLAY") {
        vars.push(("GDK_BACKEND", "x11"));
    }
    vars
}

/// Apply `changes` to a command's environment.
#[cfg(not(target_os = "android"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn scrub_command(cmd: &mut std::process::Command, changes: &ChildEnv) {
    for name in &changes.remove {
        cmd.env_remove(name);
    }
    for (name, value) in &changes.set {
        cmd.env(name, value);
    }
    // Checked now: a folder that has gone since must not stop the program.
    if let Some(dir) = changes.cwd.as_deref().filter(|dir| std::path::Path::new(dir).is_dir()) {
        cmd.current_dir(dir);
    }
}

/// Apply `changes` to a terminal command's environment (portable-pty copies
/// the whole process environment when the command is made).
#[cfg(not(target_os = "android"))]
pub(crate) fn scrub_pty(cmd: &mut portable_pty::CommandBuilder, changes: &ChildEnv) {
    for name in &changes.remove {
        cmd.env_remove(name);
    }
    for (name, value) in &changes.set {
        cmd.env(name, value);
    }
}

/// Hand `target` (a file, a folder or a URL) to the desktop's default
/// handler, without waiting for it. On Linux this tries the `open` crate's
/// own launchers (`xdg-open`, `gio open`, ...) with Solanum's variables
/// removed; elsewhere nothing was set, and `open::that_detached` is kept
/// (on Windows it is `ShellExecuteExW`, not `cmd /c start`, which would expand
/// `%VAR%` in the name).
#[cfg(not(target_os = "android"))]
pub(crate) fn open_detached(target: &OsStr) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut last_error = None;
        for mut cmd in open::commands(target) {
            scrub_command(&mut cmd, for_children());
            match spawn_detached(&mut cmd) {
                Ok(()) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no launcher found")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        open::that_detached(target)
    }
}

/// Start `cmd` in its own process group (a Ctrl+C in the terminal Solanum was
/// started from does not reach it) with no standard streams, and reap it on a
/// thread of its own, so it never lingers as a zombie.
#[cfg(target_os = "linux")]
fn spawn_detached(cmd: &mut std::process::Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
    let mut child = cmd.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
        move |name| map.get(name).cloned()
    }

    fn names(vars: &[(&'static str, &'static str)]) -> Vec<&'static str> {
        vars.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn the_gpu_workarounds_are_set_unless_the_user_set_them() {
        let all = graphics_workarounds(env_of(&[]));
        assert_eq!(
            names(&all),
            ["WEBKIT_DISABLE_HARDWARE_ACCELERATION", "WEBKIT_DISABLE_DMABUF_RENDERER", "WEBKIT_DISABLE_COMPOSITING_MODE", "LIBGL_ALWAYS_SOFTWARE"]
        );
        assert!(all.iter().all(|(_, v)| *v == "1"));
        let mine = graphics_workarounds(env_of(&[("LIBGL_ALWAYS_SOFTWARE", "0"), ("WEBKIT_DISABLE_COMPOSITING_MODE", "")]));
        assert_eq!(names(&mine), ["WEBKIT_DISABLE_HARDWARE_ACCELERATION", "WEBKIT_DISABLE_DMABUF_RENDERER"]);
    }

    /// F-014: XWayland only where it is a Wayland session that has it.
    #[test]
    fn gdk_backend_is_forced_only_on_wayland_with_xwayland() {
        let gdk = |pairs: &[(&str, &str)]| names(&graphics_workarounds(env_of(pairs))).contains(&"GDK_BACKEND");
        assert!(!gdk(&[("DISPLAY", ":0")]), "X11: nothing to change");
        assert!(gdk(&[("WAYLAND_DISPLAY", "wayland-0"), ("DISPLAY", ":0")]));
        assert!(gdk(&[("XDG_SESSION_TYPE", "wayland"), ("DISPLAY", ":1")]));
        assert!(!gdk(&[("WAYLAND_DISPLAY", "wayland-0")]), "no XWayland: GTK could not open a display");
        assert!(!gdk(&[("WAYLAND_DISPLAY", "wayland-0"), ("DISPLAY", ":0"), ("GDK_BACKEND", "wayland")]), "the user's choice stays");
    }

    #[test]
    fn programs_started_by_solanum_do_not_get_its_variables() {
        let names = ["GDK_BACKEND", "LIBGL_ALWAYS_SOFTWARE", "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"];
        let start_in = std::env::temp_dir();
        let changes = ChildEnv {
            remove: names.iter().map(OsString::from).collect(),
            set: vec![(OsString::from("PATH"), OsString::from("/usr/bin"))],
            cwd: Some(start_in.clone().into_os_string()),
        };
        let mut cmd = std::process::Command::new("xdg-open");
        cmd.env("GDK_BACKEND", "x11").env("LIBGL_ALWAYS_SOFTWARE", "1").env("KEEP", "yes").env("PATH", "/image/usr/bin:/usr/bin");
        scrub_command(&mut cmd, &changes);
        let envs: HashMap<_, _> = cmd.get_envs().map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string()))).collect();
        for name in names {
            assert_eq!(envs.get(OsStr::new(name)), Some(&None), "{name} is removed, not only left unset");
        }
        assert_eq!(envs.get(OsStr::new("KEEP")), Some(&Some(OsString::from("yes"))));
        assert_eq!(envs.get(OsStr::new("PATH")), Some(&Some(OsString::from("/usr/bin"))));
        assert_eq!(cmd.get_current_dir(), Some(start_in.as_path()));

        let mut gone = std::process::Command::new("xdg-open");
        scrub_command(&mut gone, &ChildEnv { cwd: Some(OsString::from("/no/such/folder")), ..ChildEnv::default() });
        assert_eq!(gone.get_current_dir(), None, "a folder that is gone must not stop the program from starting");

        #[cfg(not(target_os = "android"))]
        {
            let mut shell = portable_pty::CommandBuilder::new("/bin/sh");
            shell.env("GDK_BACKEND", "x11");
            shell.env("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1");
            shell.env("HOME", "/home/someone");
            shell.env("PATH", "/image/usr/bin:/usr/bin");
            scrub_pty(&mut shell, &changes);
            assert_eq!(shell.get_env("GDK_BACKEND"), None);
            assert_eq!(shell.get_env("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"), None);
            assert_eq!(shell.get_env("HOME"), Some(OsStr::new("/home/someone")));
            assert_eq!(shell.get_env("PATH"), Some(OsStr::new("/usr/bin")));
        }
    }

    /// What a child of the AppImage ends up with, as text. The image's scripts
    /// are read from a real build: `apprun-hooks/linuxdeploy-plugin-gtk.sh`
    /// and the strings in `AppRun.wrapped`.
    #[cfg(target_os = "linux")]
    mod appimage {
        use super::*;

        const IMAGE: &str = "/tmp/.mount_SolanuAbCdEf";

        /// The environment the two scripts leave, on top of the user's `before`.
        fn started_by_appimage(before: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
            let old = |name: &str| before.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string());
            let mut env: Vec<(String, String)> = before
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut put = |name: &str, value: String| {
                env.retain(|(k, _)| k != name);
                env.push((name.to_string(), value));
            };
            let keep = |name: &str| old(name).unwrap_or_default();
            // The AppImage runtime.
            put("APPIMAGE", "/home/someone/Solanum.AppImage".into());
            put("APPDIR", IMAGE.into());
            put("ARGV0", "./Solanum.AppImage".into());
            put("OWD", "/home/someone".into());
            // AppRun.wrapped.
            put("PYTHONHOME", format!("{IMAGE}/usr/"));
            put("PYTHONDONTWRITEBYTECODE", "1".into());
            put("PATH", format!("{IMAGE}/usr/bin/:{IMAGE}/usr/sbin/:{IMAGE}/usr/games/:{IMAGE}/bin/:{IMAGE}/sbin/:{}", keep("PATH")));
            put("LD_LIBRARY_PATH", format!("{IMAGE}/usr/lib/:{IMAGE}/usr/lib/x86_64-linux-gnu/:{IMAGE}/lib/:{}", keep("LD_LIBRARY_PATH")));
            put("PYTHONPATH", format!("{IMAGE}/usr/share/pyshared/:{}", keep("PYTHONPATH")));
            put("PERLLIB", format!("{IMAGE}/usr/share/perl5/:{IMAGE}/usr/lib/perl5/:{}", keep("PERLLIB")));
            put("QT_PLUGIN_PATH", format!("{IMAGE}/usr/lib/qt4/plugins/:{}", keep("QT_PLUGIN_PATH")));
            put("GST_PLUGIN_SYSTEM_PATH", format!("{IMAGE}/usr/lib/gstreamer:{}", keep("GST_PLUGIN_SYSTEM_PATH")));
            put("GST_PLUGIN_SYSTEM_PATH_1_0", format!("{IMAGE}/usr/lib/gstreamer-1.0:{}", keep("GST_PLUGIN_SYSTEM_PATH_1_0")));
            // The GTK hook, sourced before AppRun.wrapped runs: it sees the
            // user's XDG_DATA_DIRS, AppRun.wrapped then adds its own in front.
            let hooked = format!("{IMAGE}/usr/share:/usr/share:{}", keep("XDG_DATA_DIRS"));
            put("XDG_DATA_DIRS", format!("{IMAGE}/usr/share/:{hooked}"));
            put("GTK_DATA_PREFIX", IMAGE.into());
            put("GTK_THEME", "Adwaita:light".into());
            put("GDK_BACKEND", "x11".into());
            put("GSETTINGS_SCHEMA_DIR", format!("{IMAGE}/usr/share/glib-2.0/schemas/:{IMAGE}//usr/share/glib-2.0/schemas"));
            put("GI_TYPELIB_PATH", format!("{IMAGE}//usr/lib/girepository-1.0"));
            put("GTK_EXE_PREFIX", format!("{IMAGE}//usr"));
            put("GTK_PATH", format!("{IMAGE}//usr/lib/gtk-3.0"));
            put("GTK_IM_MODULE_FILE", format!("{IMAGE}//usr/lib/gtk-3.0/3.0.0/immodules.cache"));
            put("GDK_PIXBUF_MODULE_FILE", format!("{IMAGE}//usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"));
            put("GIO_EXTRA_MODULES", format!("{IMAGE}/usr/lib/x86_64-linux-gnu/gio/modules"));
            env.into_iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect()
        }

        /// The environment a child sees, given Solanum's and the changes.
        fn child_of(env: &[(OsString, OsString)], changes: &ChildEnv) -> HashMap<String, String> {
            let mut out: HashMap<OsString, OsString> = env.iter().cloned().collect();
            for name in &changes.remove {
                out.remove(name);
            }
            for (name, value) in &changes.set {
                out.insert(name.clone(), value.clone());
            }
            out.into_iter().map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())).collect()
        }

        #[test]
        fn nothing_changes_outside_an_appimage() {
            let env = vec![
                (OsString::from("PATH"), OsString::from("/usr/bin")),
                (OsString::from("GTK_THEME"), OsString::from("Mine")),
                (OsString::from("APPDIR"), OsString::from("/usr")),
            ];
            assert_eq!(undo_appimage(&env), ChildEnv::default(), "APPDIR alone is someone's own variable");
        }

        #[test]
        fn a_child_gets_the_environment_from_before_the_appimage() {
            let before = [
                ("HOME", "/home/someone"),
                ("PATH", "/home/someone/bin:/usr/bin:/bin"),
                ("LD_LIBRARY_PATH", "/opt/mine/lib"),
                ("PYTHONPATH", "/home/someone/py"),
                ("XDG_DATA_DIRS", "/usr/share/cinnamon:/usr/local/share:/usr/share"),
            ];
            let env = started_by_appimage(&before);
            let child = child_of(&env, &undo_appimage(&env));
            let expected: HashMap<String, String> = before.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            assert_eq!(child, expected);
        }

        /// With nothing of the user's underneath, what is left is removed. An
        /// empty entry would be worse than the image's folders: in
        /// `LD_LIBRARY_PATH` it means the current folder.
        #[test]
        fn a_variable_the_user_never_set_goes_away() {
            let env = started_by_appimage(&[("HOME", "/home/someone"), ("PATH", "/usr/bin")]);
            let child = child_of(&env, &undo_appimage(&env));
            let mut names: Vec<&str> = child.keys().map(String::as_str).collect();
            names.sort_unstable();
            assert_eq!(names, ["HOME", "PATH"]);
            assert_eq!(child["PATH"], "/usr/bin");
        }

        /// AppRun changes folder into the image. A program opened from there
        /// would keep the mount busy, and sit in a dead folder after Solanum quits.
        #[test]
        fn a_launched_program_does_not_start_inside_the_image() {
            let mut env = started_by_appimage(&[("HOME", "/home/someone"), ("PATH", "/usr/bin")]);
            let set = |env: &mut Vec<(OsString, OsString)>, name: &str, value: &str| {
                env.retain(|(k, _)| k != name);
                env.push((OsString::from(name), OsString::from(value)));
            };
            set(&mut env, "OWD", "/work/where/it/was/started");
            assert_eq!(undo_appimage(&env).cwd, Some(OsString::from("/work/where/it/was/started")));
            env.retain(|(k, _)| k != "OWD");
            assert_eq!(undo_appimage(&env).cwd, Some(OsString::from("/home/someone")), "extract-and-run has no OWD");
            set(&mut env, "OWD", &format!("{IMAGE}/usr"));
            assert_eq!(undo_appimage(&env).cwd, Some(OsString::from("/home/someone")), "never a folder inside the image");
            env.retain(|(k, _)| k != "HOME");
            assert_eq!(undo_appimage(&env).cwd, None, "nothing better known: left as it is");
        }

        #[test]
        fn only_entries_inside_the_image_are_taken_out() {
            let sibling = format!("{IMAGE}-other/bin");
            let env = vec![
                (OsString::from("APPIMAGE"), OsString::from("/x.AppImage")),
                (OsString::from("APPDIR"), OsString::from(format!("{IMAGE}/"))),
                (OsString::from("PATH"), OsString::from(format!("{IMAGE}/usr/bin:{sibling}::/usr/bin"))),
                (OsString::from("MINE"), OsString::from("http://example.test:8080/a::b")),
            ];
            let child = child_of(&env, &undo_appimage(&env));
            assert_eq!(child["PATH"], format!("{sibling}:/usr/bin"), "a neighbour with the same prefix stays; a variable we change loses empty entries");
            assert_eq!(child["MINE"], "http://example.test:8080/a::b", "a variable with nothing of the image is left exactly as it is");
        }

        #[test]
        fn a_value_that_is_not_text_survives() {
            let mut value = b"/image/lib:/opt/caf".to_vec();
            value.push(0xE9);
            let env = vec![
                (OsString::from("APPIMAGE"), OsString::from("/x.AppImage")),
                (OsString::from("APPDIR"), OsString::from("/image")),
                (OsString::from("LD_LIBRARY_PATH"), OsString::from_vec(value)),
            ];
            let changes = undo_appimage(&env);
            let (_, kept) = changes.set.iter().find(|(k, _)| k == "LD_LIBRARY_PATH").expect("still set");
            assert_eq!(kept.as_bytes(), b"/opt/caf\xE9");
        }

        #[test]
        fn a_root_appdir_is_not_an_image() {
            let env = vec![
                (OsString::from("APPIMAGE"), OsString::from("/x.AppImage")),
                (OsString::from("APPDIR"), OsString::from("/")),
                (OsString::from("PATH"), OsString::from("/usr/bin")),
            ];
            assert_eq!(undo_appimage(&env), ChildEnv::default(), "\"/\" is not an image: everything would count as inside it");
        }
    }
}
