package io.github.joffrey_b.solanum

import android.content.ActivityNotFoundException
import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

// Importing a profile file from the system's file picker. What the picker
// returns is a content URI, not a path, so the document is copied to a private
// file; from there the import is the desktop's (the header check, a name,
// `import_profile_save`). No storage permission is involved: the picker grants
// access to the one document chosen.
//
// The Rust side deletes the copy. One left behind by a cancelled name prompt
// is overwritten by the next pick; it is as encrypted as the file it came from.
//
// `start` and `onPicked` run on the main thread.
object ProfileImport {
    private val main = Handler(Looper.getMainLooper())
    private var pending: Invoke? = null
    private var maxBytes = 0L

    private class TooLarge : Exception()

    fun start(invoke: Invoke, limit: Long) {
        if (pending != null) {
            invoke.reject("A file picker is already open.")
            return
        }
        val activity = KeepAlive.currentActivity()
        if (activity == null) {
            invoke.reject("Solanum's window is not available.")
            return
        }
        pending = invoke
        maxBytes = limit
        try {
            activity.pickDocument()
        } catch (e: ActivityNotFoundException) {
            pending = null
            invoke.reject("This device has no file picker.")
        }
    }

    fun onPicked(context: Context, uri: Uri?) {
        val invoke = pending ?: return
        pending = null
        if (uri == null) {
            invoke.resolve(JSObject())
            return
        }
        val limit = maxBytes
        // Off the main thread: the document may be on a slow or remote provider.
        thread(name = "solanum-profile-import", isDaemon = true) {
            try {
                val staged = copyToPrivateFile(context, uri, limit)
                val answer = JSObject().put("path", staged.absolutePath)
                displayName(context, uri)?.let { answer.put("name", it) }
                main.post { invoke.resolve(answer) }
            } catch (e: TooLarge) {
                val mib = limit / (1024 * 1024)
                main.post { invoke.reject("This file is larger than any Solanum profile can be (over $mib MiB), so it was not imported.") }
            } catch (e: Exception) {
                main.post { invoke.reject("The file could not be read: ${e.message ?: e.javaClass.simpleName}") }
            }
        }
    }

    private fun copyToPrivateFile(context: Context, uri: Uri, limit: Long): File {
        val dir = File(context.cacheDir, "profile-import").apply { mkdirs() }
        val staged = File(dir, "picked.solanum")
        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IOException("the document is not available")
            input.use { from ->
                staged.outputStream().use { to ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val read = from.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > limit) throw TooLarge()
                        to.write(buffer, 0, read)
                    }
                }
            }
            return staged
        } catch (e: Exception) {
            staged.delete()
            throw e
        }
    }

    // What the provider calls the document. Rust treats it as untrusted.
    fun displayName(context: Context, uri: Uri): String? = try {
        context.contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { row -> if (row.moveToFirst() && !row.isNull(0)) row.getString(0) else null }
    } catch (e: Exception) {
        null
    }
}
