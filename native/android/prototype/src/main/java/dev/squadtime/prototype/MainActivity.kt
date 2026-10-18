package dev.squadtime.prototype

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputFilter
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.*
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private lateinit var controller: PrototypeController
    private lateinit var column: LinearLayout
    private lateinit var status: TextView
    private val worker = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private var model = JSONObject().put("screen","loading")
    private var busy = false
    private var foreground = false
    private var destroyed = false
    private val profileForm = ProfileForm()
    private var formErrors = ProfileFormErrors()
    private var nicknameField: EditText? = null
    private var relayField: EditText? = null
    private val ink = Color.rgb(27, 38, 65)
    private val purple = Color.rgb(100, 77, 218)
    private val avatars = arrayOf("🦊 Fox", "🐼 Panda", "🐙 Octopus", "🐯 Tiger")
    private val poll = object : Runnable {
        override fun run() {
            if (foreground && !busy && model.optString("screen") in setOf("request","welcome") && !model.optBoolean("confirmed")) runWork(false) { controller.refresh() }
            if (foreground) handler.postDelayed(this, 2200)
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        controller = PrototypeController(applicationContext)
        render()
        runWork { controller.load() }
    }
    override fun onResume() { super.onResume(); foreground = true; handler.removeCallbacks(poll); handler.postDelayed(poll,2200) }
    override fun onPause() { foreground = false; handler.removeCallbacks(poll); super.onPause() }
    override fun onDestroy() { destroyed = true; handler.removeCallbacksAndMessages(null); worker.shutdown(); super.onDestroy() }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun text(value: String, size: Float = 16f, bold: Boolean = false): TextView = TextView(this).apply {
        text = value; textSize = size; setTextColor(ink); setPadding(0,dp(5),0,dp(7)); if (bold) setTypeface(null,Typeface.BOLD)
    }
    private fun card(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setPadding(dp(20),dp(16),dp(20),dp(16))
        background = GradientDrawable().apply { setColor(Color.WHITE); cornerRadius = dp(22).toFloat() }
        column.addView(this,LinearLayout.LayoutParams(-1,-2).apply { bottomMargin = dp(16) })
    }
    private fun LinearLayout.button(label: String, action: () -> Unit) {
        addView(Button(this@MainActivity).apply {
            text = label; isAllCaps = false; textSize = 16f; isEnabled = !busy; setTextColor(purple)
            setOnClickListener { action() }
        }, LinearLayout.LayoutParams(-1,dp(54)).apply { topMargin = dp(5) })
    }
    private fun edit(hint: String, value: String = ""): EditText = EditText(this).apply {
        this.hint = hint; setText(value); setTextColor(ink); textSize = 17f; setSingleLine(true)
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }
    private fun render() {
        val scroll = ScrollView(this).apply { setBackgroundColor(Color.rgb(244,245,252)); isFillViewport = true }
        column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(24),dp(24),dp(24),dp(28))
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars())
                view.setPadding(dp(24),dp(24) + bars.top,dp(24),dp(28) + bars.bottom); insets
            }
        }
        scroll.addView(column)
        column.addView(text("squadtime",32f,true))
        column.addView(text("Make time for your people",16f))
        val note = card()
        note.addView(text("LOCAL DEVICE PROTOTYPE",12f,true))
        note.addView(text("Synthetic test profiles only. One direct contact and one encrypted test. No production onboarding, introductions, recovery or general chat.",14f))
        val screen = model.optString("screen")
        nicknameField = null; relayField = null
        if (screen == "profile" || screen == "home") {
            val draft = profileForm.display(ProfileDraft(model.optString("nickname"),model.optString("relay"),model.optInt("avatar")))
            val profileCard = card()
            profileCard.addView(text("Your test profile",23f,true))
            val nickname = edit("Test nickname",draft.nickname)
            nickname.filters = arrayOf(InputFilter.LengthFilter(64))
            nickname.error = formErrors.nickname
            nicknameField = nickname
            nickname.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    profileForm.edit(profileForm.current().copy(nickname = s.toString()))
                    formErrors = formErrors.copy(nickname = null); nickname.error = null
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })
            profileCard.addView(nickname)
            val avatar = Spinner(this).apply {
                adapter = ArrayAdapter(this@MainActivity,android.R.layout.simple_spinner_dropdown_item,avatars)
                setSelection(draft.avatar)
                onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                        profileForm.edit(profileForm.current().copy(avatar = position))
                    }
                    override fun onNothingSelected(parent: AdapterView<*>?) {}
                }
            }
            profileCard.addView(avatar,LinearLayout.LayoutParams(-1,dp(56)))
            profileCard.addView(text("Local test relay",17f,true))
            val relay = edit("http://192.168.1.2:8789",draft.relay)
            relay.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
            relay.error = formErrors.relay
            relayField = relay
            relay.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    profileForm.edit(profileForm.current().copy(relay = s.toString()))
                    formErrors = formErrors.copy(relay = null); relay.error = null
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })
            profileCard.addView(relay)
            profileCard.addView(text("Use the private IPv4 address of your test Mac. HTTP is allowed only on a local test network. Your profile is encrypted locally; a nickname hint is included in your QR.",13f))
            profileCard.button(if (screen == "profile") "Create local profile" else "Save profile and relay") {
                submitProfile()
            }
            if (screen == "home") {
                val connect = card()
                connect.addView(text("Meet your first contact",23f,true))
                connect.addView(text("Confirm the intended test device on both screens. A QR can be forwarded and does not prove presence, age, identity or Guardian approval.",14f))
                connect.button("Save profile and show my code") { submitProfile(showCode = true) }
                connect.button("Scan a code") { scan() }
                connect.button("Paste code · manual transfer test") { paste() }
            }
        } else if (screen !in setOf("loading","locked")) {
            val own = card()
            own.addView(text("${avatars[model.optInt("avatar")].substringBefore(' ')}  ${model.optString("nickname")}",23f,true))
            own.addView(text("Test relay: ${model.optString("relay")}",13f))
            val contact = card()
            val title = when(screen) {
                "invitation" -> "1 · Show your invitation"
                "request" -> "2 · Let your contact scan"
                "welcome" -> if (model.optBoolean("confirmed")) "Contact confirmed" else "3 · Waiting for confirmation"
                "joined" -> "Encrypted test received"
                else -> "Connection"
            }
            contact.addView(text(title,23f,true))
            if (model.has("qr")) {
                val qr = model.getString("qr")
                try {
                    val matrix = MultiFormatWriter().encode(qr,BarcodeFormat.QR_CODE,700,700)
                    val pixels = IntArray(700 * 700) { if (matrix[it % 700,it / 700]) Color.BLACK else Color.WHITE }
                    val bitmap = Bitmap.createBitmap(pixels,700,700,Bitmap.Config.ARGB_8888)
                    contact.addView(ImageView(this).apply { setImageBitmap(bitmap); contentDescription = "Squadtime ${if (screen == "invitation") "invitation" else "request"} QR code"; adjustViewBounds = true },LinearLayout.LayoutParams(-1,dp(280)))
                } catch (_: Exception) { contact.addView(text("QR display unavailable. Use manual transfer.")) }
                contact.addView(text("Expires in ${maxOf(0,model.getLong("expiresAt") - System.currentTimeMillis() / 1000)} seconds. Reset this prototype to start a new exchange after expiry.",13f))
                contact.button("View manual transfer code") {
                    AlertDialog.Builder(this).setTitle("Manual code-transfer test").setMessage(qr)
                        .setNegativeButton("Close",null).setPositiveButton("Copy public test code") { _, _ ->
                            val clip = android.content.ClipData.newPlainText("Squadtime public test code",qr)
                            clip.description.extras = android.os.PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE",true) }
                            (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager).setPrimaryClip(clip)
                            status.text = "Public test code copied. Manual transfer does not demonstrate proximity."
                        }.show()
                }
            }
            when(screen) {
                "invitation" -> {
                    contact.addView(text("Your contact scans this invitation and confirms your fingerprint. Then scan the request shown on their device.",15f))
                    contact.button("Scan contact’s request") { scan() }
                    contact.button("Paste request · manual transfer test") { paste() }
                }
                "request" -> contact.addView(text("Ask your contact to scan this request and confirm your device. Keep this screen open while waiting for the encrypted test.",15f))
                "welcome" -> contact.addView(text(if (model.optBoolean("confirmed")) "The other device signed a receipt after joining and receiving the fixed encrypted test." else "Your committed Welcome is ready. Waiting for the other device to receive the fixed encrypted test and return its signed receipt.",15f))
                "joined" -> {
                    contact.addView(text("The real MLS Welcome and fixed synthetic probe were authenticated and committed locally. This is an interoperability test, not a general messaging feature.",15f))
                    contact.addView(text(if (model.optInt("pending") > 0) "Test remains in your encrypted inbox across restart." else "Test inbox acknowledged.",14f))
                    if (model.optInt("pending") > 0) contact.button("Acknowledge encrypted test") { runWork { controller.acknowledge() } }
                }
            }
            if (model.optString("peerLabel").isNotBlank()) contact.addView(text("Contact hint: ${model.optString("peerLabel")}",16f,true))
            if (model.has("peerFingerprint")) contact.addView(text("Confirmed contact key\n${groupFingerprint(model.getString("peerFingerprint"))}",13f))
            contact.addView(text("Your device key\n${groupFingerprint(model.optString("fingerprint"))}",13f))
            if (model.optBoolean("manual")) contact.addView(text("Manual code-transfer test. This does not demonstrate proximity.",14f,true))
            contact.button("Retry exact saved exchange") { runWork { controller.refresh() } }
        } else {
            card().addView(text(if (screen == "locked") "Local data cannot be opened. A missing or replaced key will not be regenerated. Reset is required to create a new synthetic profile." else "Opening encrypted local storage…",17f))
        }
        status = text(if (busy) "Working…" else "",14f)
        status.accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        column.addView(status)
        if (screen != "profile" && screen != "loading") column.button("Reset this prototype") {
            AlertDialog.Builder(this).setTitle("Delete this prototype’s local data?")
                .setMessage("This deletes the test profile, device keys, contact and encrypted inbox belonging to Squadtime DEV on this device. Recovery is not supported.")
                .setNegativeButton("Cancel",null).setPositiveButton("Delete local prototype data") { _, _ -> runWork(onSuccess = { profileForm.committed(); formErrors = ProfileFormErrors(); render() }) { controller.reset() } }.show()
        }
        setContentView(scroll)
    }
    private fun groupFingerprint(value: String) = value.chunked(4).joinToString(" ")
    private fun submitProfile(showCode: Boolean = false) {
        if (busy) return
        formErrors = profileForm.validate(requireRelay = showCode)
        nicknameField?.error = formErrors.nickname
        relayField?.error = formErrors.relay
        if (formErrors.hasErrors) {
            status.text = "Check the highlighted fields. Your entries have been kept."
            if (formErrors.nickname != null) nicknameField?.requestFocus() else relayField?.requestFocus()
            return
        }
        val draft = profileForm.current()
        runWork(
            failureMessage = "Could not save the local profile securely. Your entries have been kept. Check device storage and retry. A missing local key requires an explicit reset; it will not be replaced automatically.",
            onSuccess = {
                profileForm.committed(); formErrors = ProfileFormErrors(); render()
                if (showCode) runWork { controller.showCode() }
            }
        ) { controller.saveProfile(draft.nickname,draft.avatar,draft.relay) }
    }
    private fun runWork(showBusy: Boolean = true,
                        failureMessage: String = "Could not complete the encrypted test. Check the relay connection, code expiry and selected device. Saved keys and committed outboxes are retained; retry or explicitly reset.",
                        onSuccess: (() -> Unit)? = null, operation: () -> JSONObject) {
        if (busy || destroyed) return
        busy = true
        if (showBusy) render()
        worker.execute {
            var failure = false
            val result = try { operation() } catch (_: Exception) {
                failure = true
                if (model.optString("screen") == "loading") JSONObject().put("screen","locked")
                else runCatching { controller.load() }.getOrElse { JSONObject().put("screen","locked") }
            }
            handler.post {
                if (!destroyed) {
                    busy = false; model = result; render()
                    if (failure) status.text = failureMessage else onSuccess?.invoke()
                }
            }
        }
    }
    private fun scan() { if (!busy) startActivityForResult(Intent(this,ScannerActivity::class.java),42) }
    private fun paste() {
        val field = edit("Paste a Squadtime prototype code").apply { setSingleLine(false); filters = arrayOf(InputFilter.LengthFilter(2048)) }
        AlertDialog.Builder(this).setTitle("Manual code-transfer test").setMessage("This mode does not demonstrate proximity. Compare the full device fingerprint through a trusted channel.")
            .setView(field).setNegativeButton("Cancel",null).setPositiveButton("Review code") { _, _ -> reviewCode(field.text.toString().trim(),true) }.show()
    }
    @Deprecated("Activity callback retained for this small platform-Views prototype")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode,resultCode,data)
        if (requestCode == 42 && resultCode == RESULT_OK) reviewCode(data?.getStringExtra("code") ?: "",false)
        else if (requestCode == 42) status.text = "Scan cancelled or camera permission denied. Retry and allow camera access in Android Settings, or use the labelled manual transfer test."
    }
    private fun reviewCode(value: String, manual: Boolean) {
        val qr = try {
            PrototypeProtocol.parseQr(value).also {
                if (model.optString("relay").isNotBlank()) require(it.getString("relay") == model.getString("relay"))
            }
        } catch (_: Exception) { status.text = "Invalid, expired or mismatched test code. No network request was made."; return }
        val fingerprint = groupFingerprint(PrototypeProtocol.digest(PrototypeProtocol.decode(qr.getString("key"))))
        AlertDialog.Builder(this).setTitle("Confirm the intended test device")
            .setMessage("Nickname hint: ${qr.getString("label")}\n\nCompare this full fingerprint on the other device:\n$fingerprint\n\nTest server: ${qr.getString("relay")}\n\n${if (manual) "Manual transfer does not demonstrate proximity." else "A QR can be forwarded; scanning does not prove presence."}\nThis does not verify identity, age or Guardian approval.")
            .setNegativeButton("Cancel",null).setPositiveButton("Keys match · allow test server") { _, _ ->
                runWork { controller.acceptCode(PrototypeProtocol.parseQr(value),manual) }
            }.show()
    }
}
