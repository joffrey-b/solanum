package io.github.joffrey_b.solanum

import android.content.ActivityNotFoundException
import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

// Exporting a profile through the system's "Save as" screen. The vault file is
// copied as it is, encrypted, to the document the user creates; only Rust says
// which file. No storage permission: the screen grants access to that document.
//
// `start` and `onChosen` run on the main thread.
object ProfileExport {
    private val main = Handler(Looper.getMainLooper())
    private var pending: Invoke? = null
    private var source: File? = null
    private var suggested = ""

    fun start(invoke: Invoke, path: String, name: String) {
        if (pending != null) {
            invoke.reject("A save screen is already open.")
            return
        }
        val activity = KeepAlive.currentActivity()
        if (activity == null) {
            invoke.reject("Solanum's window is not available.")
            return
        }
        pending = invoke
        source = File(path)
        suggested = name
        try {
            activity.createDocument(name)
        } catch (e: ActivityNotFoundException) {
            pending = null
            source = null
            invoke.reject("This device has no save screen.")
        }
    }

    fun onChosen(context: Context, uri: Uri?) {
        val invoke = pending ?: return
        val file = source
        val fallbackName = suggested
        pending = null
        source = null
        if (uri == null || file == null) {
            invoke.resolve(JSObject())
            return
        }
        // Off the main thread: the document may be on a slow or remote provider.
        thread(name = "solanum-profile-export", isDaemon = true) {
            try {
                write(context, file, uri)
                val name = ProfileImport.displayName(context, uri) ?: fallbackName
                main.post { invoke.resolve(JSObject().put("name", name)) }
            } catch (e: Exception) {
                // Half a backup must not pass for a backup.
                val removed = try {
                    DocumentsContract.deleteDocument(context.contentResolver, uri)
                } catch (_: Exception) {
                    false
                }
                val reason = e.message ?: e.javaClass.simpleName
                val leftover = if (removed) "" else " An incomplete file may be left there: delete it."
                main.post { invoke.reject("The profile could not be saved there: $reason.$leftover") }
            }
        }
    }

    private fun write(context: Context, source: File, uri: Uri) {
        source.inputStream().use { from ->
            // "wt": plain "w" leaves the old tail in place on some providers.
            val output = context.contentResolver.openOutputStream(uri, "wt")
                ?: throw IOException("the location is not available")
            output.use { from.copyTo(it, 64 * 1024) }
        }
    }
}
