package dev.squadtime.prototype

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory

/** Private scanner: no URI handlers and no third-party intents receive scanned content. */
class ScannerActivity : Activity() {
    private lateinit var scanner: DecoratedBarcodeView
    private var active = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 32, 24, 24) }
        column.addView(TextView(this).apply { text = "Scan your contact’s Squadtime code\nA scan does not prove physical presence or identity."; textSize = 18f })
        scanner = DecoratedBarcodeView(this).apply {
            barcodeView.decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))
            setStatusText("Align the QR code inside the frame")
            decodeSingle(object : BarcodeCallback {
                override fun barcodeResult(result: BarcodeResult) {
                    val value = result.text ?: return
                    if (value.length > 8192) { setResult(RESULT_CANCELED); finish(); return }
                    setResult(RESULT_OK, Intent().putExtra("code", value)); finish()
                }
            })
        }
        column.addView(scanner, LinearLayout.LayoutParams(-1, 0, 1f))
        column.addView(Button(this).apply { text = "Cancel scan"; setOnClickListener { finish() } })
        setContentView(column)
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) requestPermissions(arrayOf(Manifest.permission.CAMERA), 41)
    }
    override fun onResume() {
        super.onResume()
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) { scanner.resume(); active = true }
    }
    override fun onPause() { if (active) scanner.pause(); active = false; super.onPause() }
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 41 && grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) { scanner.resume(); active = true }
        else { setResult(RESULT_CANCELED); finish() }
    }
}
