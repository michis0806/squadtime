package dev.squadtime.proof

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "Squadtime native pairing proof\nRun instrumentation tests for evidence.\nNo account or production enrollment."
            setPadding(32, 64, 32, 32)
        })
    }
}
