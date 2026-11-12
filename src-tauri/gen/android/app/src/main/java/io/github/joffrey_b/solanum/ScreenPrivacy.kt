package io.github.joffrey_b.solanum

import android.app.Activity
import android.content.Context
import android.view.WindowManager

// Settings > "Hide Solanum from screenshots and Recents" (FLAG_SECURE): Android
// then blanks Solanum's window in screenshots, screen recordings, casting and
// the Recents preview. It does not stop accessibility services, which read the
// screen's text. On by default; kept here rather than in the window's storage
// so that MainActivity applies it before the first frame, profile picker
// included.
object ScreenPrivacy {
    private const val KEY = "secure_screen"

    fun isOn(context: Context): Boolean =
        context.getSharedPreferences(KeepAlive.PREFS, Context.MODE_PRIVATE).getBoolean(KEY, true)

    fun set(context: Context, on: Boolean) {
        context.getSharedPreferences(KeepAlive.PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, on).apply()
    }

    fun apply(activity: Activity) {
        if (isOn(activity)) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
