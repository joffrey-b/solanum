package io.github.joffrey_b.solanum

import android.Manifest
import android.graphics.Color
import android.os.Bundle
import android.view.View
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  // Registered here, not through Tauri: Tauri's own permission launcher
  // stays bound to the first Activity of the process (F-033).
  private val notificationPermission =
    registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
      KeepAlive.onNotificationAnswer(applicationContext, granted)
    }

  fun askNotificationPermission() {
    notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
  }

  // Importing a profile (ProfileImport). Any type: `.solanum` has no MIME type
  // of its own, and Rust checks the file's header.
  private val profilePicker =
    registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
      ProfileImport.onPicked(applicationContext, uri)
    }

  fun pickDocument() {
    profilePicker.launch(arrayOf("*/*"))
  }

  // Exporting a profile (ProfileExport).
  private val profileSaver =
    registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
      ProfileExport.onChosen(applicationContext, uri)
    }

  fun createDocument(suggestedName: String) {
    profileSaver.launch(suggestedName)
  }

  // Android 15+ (API 35) forces edge-to-edge — `setDecorFitsSystemWindows`
  // and the deprecated translucent-status-bar flags are ignored when
  // targetSdk >= 35. Our compileSdk/targetSdk are both 36, so the WebView
  // is laid out behind the status bar and our React tab strip overlaps
  // the system clock.
  //
  // Fix: attach an OnApplyWindowInsetsListener to android.R.id.content and
  // pass system-bar + cutout + IME insets in as padding. The WebView then
  // mounts inside that padded region — tabs sit right below the status
  // bar, and when the soft keyboard opens the bottom padding grows by the
  // IME height so the terminal + MobileKeyBar stay visible above it.
  //
  // The IME inset is required because Android 15 edge-to-edge decouples
  // the WebView from the Activity's adjustResize behaviour: the manifest
  // still has adjustResize + stateHidden, but with
  // setDecorFitsSystemWindows(false) the WebView receives the IME as an
  // inset instead of a window resize, so we have to apply it manually or
  // the keyboard draws over the content.
  //
  // The status-bar + nav-bar colour setters are deprecated in API 35 and
  // ignored once edge-to-edge is forced: the band behind the bars is then the
  // content view's padding, which shows the window's (light theme) background
  // unless the view paints its own. So the content view is painted #0d0d10,
  // and the system bars get light icons over it (N-036). The colour setters
  // stay for Android 14 and older.
  override fun onCreate(savedInstanceState: Bundle?) {
    // Before anything is drawn, the profile picker included.
    ScreenPrivacy.apply(this)
    super.onCreate(savedInstanceState)

    // Back on the main screen sends Solanum to the background. Without this
    // it finishes the Activity, on Android 16 too (the emulator, batch 13:
    // Android 12+'s "a root activity goes to the background" does not happen
    // here), and Tauri then exits, ending every session (N-034). The price is
    // Android 16's predictive back-to-home animation. Swiping Solanum away
    // from Recents still closes it.
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        moveTaskToBack(true)
      }
    })

    window.statusBarColor = Color.parseColor("#0d0d10")
    window.navigationBarColor = Color.parseColor("#0d0d10")
    WindowCompat.getInsetsController(window, window.decorView).apply {
      isAppearanceLightStatusBars = false
      isAppearanceLightNavigationBars = false
    }
    val content = findViewById<View>(android.R.id.content)
    content.setBackgroundColor(Color.parseColor("#0d0d10"))
    ViewCompat.setOnApplyWindowInsetsListener(content) { v, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars()
          or WindowInsetsCompat.Type.displayCutout()
      )
      val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
      v.setPadding(
        bars.left,
        bars.top,
        bars.right,
        maxOf(bars.bottom, ime.bottom)
      )
      WindowInsetsCompat.CONSUMED
    }
  }

  // The keep-alive service runs while the window has SSH sessions open
  // (KeepAlive). A start Android refused in the background, or a service it
  // ended, is retried here.
  override fun onStart() {
    super.onStart()
    KeepAlive.onActivityStarted(this)
  }

  // Any destroy other than for a configuration change (finished, swiped
  // away, or destroyed by Android in the background) ends the app's Rust side
  // too: tao reports the window destroyed and Tauri exits, tearing every
  // session down. So the keep-alive goes with it (F-032). configChanges in
  // the manifest makes a configuration-change destroy rare.
  override fun onDestroy() {
    if (!isChangingConfigurations) {
      KeepAlive.onActivityGone(this)
    }
    super.onDestroy()
  }
}
