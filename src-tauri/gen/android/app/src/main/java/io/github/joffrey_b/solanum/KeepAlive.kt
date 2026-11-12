package io.github.joffrey_b.solanum

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.appcompat.app.AlertDialog
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import java.lang.ref.WeakReference

// What keeps Solanum's process alive while SSH sessions are open (F-004,
// F-032, F-033). All SSH state lives in the Rust backend in this process, and
// a foreground service with a visible notification is how Android is told
// not to kill it while the user is in another app.
//
// The window says how many SSH session tabs it has (Rust command
// `android_keep_alive` -> KeepAlivePlugin.setSessions). The service runs while
// that number is above 0, and stops at 0, when the Activity is destroyed
// (other than for a configuration change), or when Solanum is swiped away from
// Recents. Session tabs rather than connections:
// a session waiting to reconnect has no connection for a while, and Android
// 12+ does not let a background app start the service again afterwards.
//
// Everything here runs on the main thread (plugin commands are posted there).
object KeepAlive {
    private const val TAG = "SolanumKeepAlive"
    const val PREFS = "solanum"
    private const val ASKED_NOTIFICATIONS = "notifications_asked"
    private const val CHANNEL_ID = "solanum_background"
    const val NOTIFICATION_ID = 1042
    private const val NOTICE_ID = 1043

    private enum class State { STOPPED, STARTING, RUNNING }

    var sessions = 0
        private set
    private var state = State.STOPPED
    private var service: WeakReference<ConnectionKeeperService>? = null
    private var activity: WeakReference<MainActivity>? = null
    private var asking = false
    private var question: AlertDialog? = null

    fun setSessions(context: Context, count: Int) {
        val before = sessions
        sessions = maxOf(count, 0)
        if (sessions == 0) {
            stop(context)
            return
        }
        when (state) {
            State.STOPPED -> start(context)
            State.STARTING -> {} // onStartCommand reads the count
            State.RUNNING -> postNotification(context)
        }
        if (before == 0) {
            activity?.get()?.let { askForNotifications(it) }
        }
    }

    fun currentActivity(): MainActivity? = activity?.get()

    // A start refused in the background, or a service Android ended
    // (onTimeout), comes back once the user is in Solanum again.
    fun onActivityStarted(activity: MainActivity) {
        this.activity = WeakReference(activity)
        if (sessions > 0 && state == State.STOPPED) start(activity.applicationContext)
    }

    // The Activity is gone, other than for a configuration change: finished,
    // swiped away, or destroyed by Android. Tauri then reports its window
    // destroyed and exits, and that teardown ends every session (tao does not
    // look at isFinishing). Nothing is left to keep alive, and a service kept
    // now would only hold a torn-down process with a wrong notification.
    fun onActivityGone(activity: MainActivity) {
        if (this.activity?.get() === activity) this.activity = null
        question?.dismiss()
        question = null
        asking = false
        sessions = 0
        stop(activity.applicationContext)
    }

    fun onTaskRemoved(context: Context) {
        sessions = 0
        stop(context)
    }

    private fun start(context: Context) {
        try {
            ContextCompat.startForegroundService(context, Intent(context, ConnectionKeeperService::class.java))
            state = State.STARTING
            NotificationManagerCompat.from(context).cancel(NOTICE_ID)
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException: Android 12+ refuses
            // while Solanum is in the background. onActivityStarted retries.
            Log.w(TAG, "keep-alive not started: $e")
        }
    }

    private fun stop(context: Context) {
        // While STARTING, onStartCommand calls startForeground first and then
        // stops the service itself: stopping it before startForeground makes
        // some Android versions crash the app.
        if (state == State.RUNNING) {
            context.stopService(Intent(context, ConnectionKeeperService::class.java))
            state = State.STOPPED
            service = null
        }
    }

    // Called by the service right after its startForeground.
    fun onServiceForeground(service: ConnectionKeeperService) {
        this.service = WeakReference(service)
        state = State.RUNNING
        if (sessions == 0) {
            service.stopSelf()
            state = State.STOPPED
            this.service = null
        }
    }

    fun onServiceDestroyed(service: ConnectionKeeperService) {
        if (this.service?.get() === service) {
            this.service = null
            state = State.STOPPED
        }
    }

    // Android ended the service (a foreground-service time limit). Say so;
    // onActivityStarted starts it again while sessions remain.
    fun onServiceTimedOut(service: ConnectionKeeperService) {
        if (canNotify(service)) {
            val notice = NotificationCompat.Builder(service, ensureChannel(service))
                .setContentTitle("Solanum is no longer kept running")
                .setContentText("Android ended its background time. Open Solanum to keep your sessions.")
                .setSmallIcon(R.drawable.ic_stat_solanum)
                .setContentIntent(openApp(service))
                .setAutoCancel(true)
                .build()
            NotificationManagerCompat.from(service).notify(NOTICE_ID, notice)
        }
        onServiceDestroyed(service)
    }

    fun notification(context: Context): Notification {
        val text = when (sessions) {
            0 -> "Keeping your SSH sessions open"
            1 -> "Keeping 1 SSH session open"
            else -> "Keeping $sessions SSH sessions open"
        }
        return NotificationCompat.Builder(context, ensureChannel(context))
            .setContentTitle("Solanum")
            .setContentText(text)
            // A monochrome icon: the adaptive launcher icon is drawn as a
            // white blob, and adaptive small icons are reported to crash the
            // system UI on Android 8.0.
            .setSmallIcon(R.drawable.ic_stat_solanum)
            .setOngoing(true)
            .setContentIntent(openApp(context))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun postNotification(context: Context) {
        if (canNotify(context)) {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification(context))
        }
    }

    private fun canNotify(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        } else {
            NotificationManagerCompat.from(context).areNotificationsEnabled()
        }

    // Tapping a notification brings the existing Activity back (singleTask).
    private fun openApp(context: Context): PendingIntent? {
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
        return PendingIntent.getActivity(
            context, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun ensureChannel(context: Context): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(CHANNEL_ID, "Background sessions", NotificationManager.IMPORTANCE_LOW)
                channel.description = "Shown while Solanum keeps SSH sessions open in the background."
                channel.setShowBadge(false)
                nm.createNotificationChannel(channel)
            }
        }
        return CHANNEL_ID
    }

    // Android 13+ hides notifications until the user allows them. Asked once
    // per install, at the first session, after a short explanation; the
    // system settings change it later (F-033).
    private fun askForNotifications(activity: MainActivity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || asking) return
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) return
        val prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(ASKED_NOTIFICATIONS, false)) return
        if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        asking = true
        question = AlertDialog.Builder(activity)
            .setTitle("Notifications")
            .setMessage(
                "While SSH sessions are open, Solanum keeps running in the background, " +
                    "and Android shows a notification saying so. Allow notifications to see it.",
            )
            .setPositiveButton("Continue") { _, _ -> activity.askNotificationPermission() }
            .setNegativeButton("No thanks") { _, _ -> answered(activity) }
            .setOnCancelListener { answered(activity) }
            // Also when it goes without an answer, so a later session asks.
            .setOnDismissListener { asking = false; question = null }
            .show()
    }

    private fun answered(context: Context) {
        asking = false
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(ASKED_NOTIFICATIONS, true).apply()
    }

    // The system prompt's answer. A notification posted while notifications
    // were blocked is not shown later by itself, so post it again.
    fun onNotificationAnswer(context: Context, granted: Boolean) {
        answered(context)
        if (granted && state == State.RUNNING) postNotification(context)
    }
}
