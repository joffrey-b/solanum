package io.github.joffrey_b.solanum

import android.app.Activity
import android.os.Handler
import android.os.Looper
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class SessionsArgs {
    var count: Int = 0
}

@InvokeArg
class ScreenPrivacyArgs {
    var on: Boolean = true
}

@InvokeArg
class PickProfileArgs {
    var maxBytes: Long = 0
}

@InvokeArg
class SaveProfileArgs {
    var path: String = ""
    var name: String = ""
}

// The Kotlin side of `src-tauri/src/android.rs`. Only Rust calls these
// commands (`run_mobile_plugin_async`); the webview cannot, since no
// capability grants them.
//
// Tauri builds this once per process with the first Activity and keeps it, so
// nothing here may use that Activity: a recreated one replaces it. KeepAlive
// holds the current one.
@TauriPlugin
class KeepAlivePlugin(activity: Activity) : Plugin(activity) {
    private val app = activity.applicationContext
    private val main = Handler(Looper.getMainLooper())

    @Command
    fun setSessions(invoke: Invoke) {
        val args = invoke.parseArgs(SessionsArgs::class.java)
        main.post { KeepAlive.setSessions(app, args.count) }
        invoke.resolve()
    }

    @Command
    fun getScreenPrivacy(invoke: Invoke) {
        invoke.resolve(JSObject().put("on", ScreenPrivacy.isOn(app)))
    }

    @Command
    fun setScreenPrivacy(invoke: Invoke) {
        val args = invoke.parseArgs(ScreenPrivacyArgs::class.java)
        main.post {
            ScreenPrivacy.set(app, args.on)
            KeepAlive.currentActivity()?.let { ScreenPrivacy.apply(it) }
            invoke.resolve()
        }
    }

    @Command
    fun pickProfileFile(invoke: Invoke) {
        val args = invoke.parseArgs(PickProfileArgs::class.java)
        main.post { ProfileImport.start(invoke, args.maxBytes) }
    }

    @Command
    fun saveProfileFile(invoke: Invoke) {
        val args = invoke.parseArgs(SaveProfileArgs::class.java)
        main.post { ProfileExport.start(invoke, args.path, args.name) }
    }
}
