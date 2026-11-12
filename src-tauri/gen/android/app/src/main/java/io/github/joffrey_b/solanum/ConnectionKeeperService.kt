package io.github.joffrey_b.solanum

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat

// Foreground service whose only job is to hold the process alive while SSH
// sessions are open and the user is in another app. It does no work itself;
// KeepAlive decides when it runs and what its notification says.
//
// Its type (F-004): `specialUse` on Android 14+, where it exists, because
// `dataSync` gets 6 hours a day on Android 15+ and keep-alive is open-ended;
// `dataSync` on Android 10 to 13, where it has no limit; none below 10.
class ConnectionKeeperService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val type = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE ->
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            else -> 0
        }
        // Always first: a service started with startForegroundService that
        // does not call startForeground in time crashes the app.
        ServiceCompat.startForeground(this, KeepAlive.NOTIFICATION_ID, KeepAlive.notification(this), type)
        KeepAlive.onServiceForeground(this)
        // Not restarted by the system after a kill: the process, and with it
        // every session, is gone by then, and the window starts it again.
        return START_NOT_STICKY
    }

    // A foreground-service time limit ran out (Android 15+ for dataSync,
    // which this service uses only below 14; Android 14's onTimeout(Int) is
    // for shortService). The service must stop within seconds, or Android
    // ends the app; KeepAlive starts it again when Solanum is opened.
    override fun onTimeout(startId: Int, fgsType: Int) {
        timedOut()
    }

    override fun onTimeout(startId: Int) {
        timedOut()
    }

    private fun timedOut() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
        KeepAlive.onServiceTimedOut(this)
    }

    // Swiped away from Recents: that is how the user closes Solanum.
    override fun onTaskRemoved(rootIntent: Intent?) {
        KeepAlive.onTaskRemoved(applicationContext)
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        KeepAlive.onServiceDestroyed(this)
        super.onDestroy()
    }
}
