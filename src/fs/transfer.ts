import { invoke } from "@tauri-apps/api/core";
import { FileProvider, RemoteFileProvider } from "./types";

// Cross-pane transfer dispatch. Instead of streaming the file through JS, we
// pick the most direct backend command for each (source, destination) pair so
// large files don't have to materialise in the renderer's memory.
//
//   remote → local, file : sftp_download_file  (streams to disk)
//   remote → local, dir  : sftp_download_dir   (recursive, streams to disk)
//   local  → remote, file: sftp_upload_file    (streams from disk)
//   local  → remote, dir : sftp_upload_dir     (recursive, streams from disk)
//   remote → remote      : sftp_rename         (server-side move)
//   local  → local       : local_rename        (in-process move)

export interface TransferSource {
  provider: FileProvider;
  /** Full path of the file being moved. */
  path: string;
  /** Base name — used to derive the destination path (except for downloads,
   *  which the backend names after the remote item itself). */
  name: string;
  isDir: boolean;
}

export interface TransferTarget {
  provider: FileProvider;
  /** Directory the file should land in. */
  dir: string;
}

// `overwrite=false` (default) makes the backend reject pre-existing
// destinations with the `EXISTS:<path>` sentinel — callers should catch
// that, surface the overwrite prompt, and re-call with `overwrite=true`.
// Drag-drop used to clobber silently; that's no longer the default
// because users couldn't tell when they'd just overwritten work.
export async function transferFile(
  src: TransferSource,
  dest: TransferTarget,
  overwrite: boolean = false,
): Promise<void> {
  // remote → local : SFTP download streams straight to disk. Both commands take
  // only the destination FOLDER: the backend names the file (or, for a
  // directory, the folder it creates, matching scp -r) after the remote item,
  // because the server chose that name and only Rust can check it is safe to
  // use as a local path.
  if (src.provider.id === "remote" && dest.provider.id === "local") {
    // A real file name never contains "/" or NUL; such a listing would be saved
    // under a different name than the one shown.
    if (src.name.includes("/") || src.name.includes("\0")) {
      throw new Error(`the server listed "${src.name}", which is not a single file name`);
    }
    await invoke(src.isDir ? "sftp_download_dir" : "sftp_download_file", {
      sessionId: (src.provider as RemoteFileProvider).sessionId,
      remotePath: src.path,
      localDir: dest.dir,
      overwrite,
    });
    return;
  }

  // local → remote: SFTP upload reads straight from disk. Same
  // parent-only convention for directories as the download side above.
  if (src.provider.id === "local" && dest.provider.id === "remote") {
    await invoke(src.isDir ? "sftp_upload_dir" : "sftp_upload_file", {
      sessionId: (dest.provider as RemoteFileProvider).sessionId,
      localPath: src.path,
      remotePath: src.isDir ? dest.dir : dest.provider.joinPath(dest.dir, src.name),
      overwrite,
    });
    return;
  }

  // Same-side moves (including directories — an OS/SFTP rename works on
  // either) go through the provider's own rename.
  await src.provider.rename(src.path, dest.provider.joinPath(dest.dir, src.name));
}
