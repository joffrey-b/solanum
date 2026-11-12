# Licences of what builds the AppImage

The AppImage holds a few pieces that come from the tools Tauri's bundler uses
to make it, not from the build machine's packages. `scripts/appimage-licenses.mjs`
puts these texts into the image's notice (`usr/share/doc/solanum/APPIMAGE-LIBRARIES.txt`),
and stops the build if the AppImage runtime names a part that has no text here.
Copied from each project's repository on 2026-11-12; check them again when a
tool changes.

| File | Covers | From |
|---|---|---|
| `linuxdeploy.txt` | `AppRun` (the script linuxdeploy writes) | https://github.com/linuxdeploy/linuxdeploy, `LICENSE.txt` |
| `appimagekit.txt` | `AppRun.wrapped` (AppImageKit's `AppRun.c`, built by Tauri: https://github.com/tauri-apps/binary-releases) | https://github.com/AppImage/AppImageKit, `LICENSE` |
| `linuxdeploy-plugin-gtk.txt` | `apprun-hooks/linuxdeploy-plugin-gtk.sh` | https://github.com/tauri-apps/linuxdeploy-plugin-gtk, `LICENSE.txt` |
| `type2-runtime.txt` | the AppImage runtime ("runtime") | https://github.com/AppImage/type2-runtime, `LICENSE` |
| `musl.txt` | the runtime's C library ("musl libc") | https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT |
| `libfuse.txt` | the runtime's "libfuse" (LGPL-2.1) | https://github.com/libfuse/libfuse, `LGPL2.txt` |
| `squashfuse.txt` | the runtime's "squashfuse" | https://github.com/vasi/squashfuse, `LICENSE` |
| `zstd.txt` | the runtime's "libzstd" | https://github.com/facebook/zstd, `LICENSE` |
| `zlib.txt` | the runtime's "zlib" | https://github.com/madler/zlib, `LICENSE` |

The runtime is passed on as AppImage's own release builds it; its source, the
libfuse it links included, is at https://github.com/AppImage/type2-runtime.
