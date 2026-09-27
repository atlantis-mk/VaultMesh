package com.vaultmesh.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Credential-encrypted storage is available after OS user unlock; never opens the Vault. */
class DeviceAssistResumeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            DeviceAssistService.startIfEnabled(context)
        }
    }
}
