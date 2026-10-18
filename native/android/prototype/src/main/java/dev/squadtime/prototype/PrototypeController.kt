package dev.squadtime.prototype

import android.content.Context
import dev.squadtime.pairing.DurableAdmission
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID

/** Serialized by the activity worker; only committed native outboxes reach transport. */
class PrototypeController(private val context: Context) {
    private val store = ProfileStore(context)
    private var profile: JSONObject? = null
    fun load(): JSONObject {
        profile = store.read()
        return view()
    }
    fun saveProfile(nickname: String, avatar: Int, relay: String): JSONObject {
        require(PrototypeProtocol.validLabel(nickname) && avatar in 0..3)
        if (relay.isNotBlank()) PrototypeProtocol.origin(relay)
        val initial = profile == null
        val next = profile ?: JSONObject()
        check(!next.has("id"))
        next.put("nickname", nickname).put("avatar", avatar).put("relay", relay)
        store.save(next, initial); profile = next
        return view()
    }
    private fun save() = store.save(profile ?: error("Profile required"))
    private fun vault(): DurableAdmission = DurableAdmission.open(context, profile!!.getString("id"))
    private fun initialOutbox(admission: DurableAdmission): dev.squadtime.pairing.AdmissionPublicResult {
        // A crash after creation but before the first commit may leave only the created phase.
        return try { admission.resume() } catch (_: Exception) {
            val p = profile!!
            if (p.getString("role") == "owner") admission.ownerStart(System.currentTimeMillis() / 1000)
            else admission.joinerStart(p.getString("invitation"), System.currentTimeMillis() / 1000)
        }
    }
    fun showCode(): JSONObject {
        val p = profile ?: error("Create your test profile first")
        require(p.getString("relay").isNotBlank())
        check(!p.has("id"))
        val id = UUID.randomUUID().toString()
        val session = ByteArray(32).apply { SecureRandom().nextBytes(this) }.joinToString("") { "%02x".format(it.toInt() and 255) }
        p.put("id",id).put("role","owner").put("session",session)
        save()
        DurableAdmission.createOwner(context,id).use { it.ownerStart(System.currentTimeMillis() / 1000) }
        return refresh()
    }
    fun acceptCode(qr: JSONObject, manual: Boolean, verificationMethod: String = if (manual) "manual" else "qr"): JSONObject {
        require(verificationMethod in setOf("manual","qr","bluetooth"))
        val p = profile ?: error("Create your test profile first")
        val relay = qr.getString("relay")
        if (p.optString("relay").isNotBlank()) require(p.getString("relay") == relay)
        if (verificationMethod == "bluetooth" && p.has("id") && p.getString("role") == "joiner") {
            vault().use { require(it.resume().kind == "request") }
            require(qr.getString("type") == "invite" && p.getString("session") == qr.getString("session") &&
                p.getString("peerKey") == qr.getString("key") && p.getString("invitationHash") == qr.getString("hash"))
            p.put("verificationMethod","bluetooth").put("manual",false); save()
            vault().use { PrototypeProtocol.exchange(relay,p.getString("session"),"request",it.resume().outbox) }
            return view()
        }
        if (!p.has("id")) {
            require(qr.getString("type") == "invite")
            val invitation = PrototypeProtocol.exchange(relay,qr.getString("session"),"invitation") ?: error("Invitation missing; ask the owner to retry")
            require(PrototypeProtocol.hash(invitation) == qr.getString("hash"))
            val native = JSONObject(PrototypeProtocol.decode(invitation).toString(Charsets.UTF_8))
            require(native.getString("adminPublicKey") == qr.getString("key") && native.getLong("expiresAt") == qr.getLong("expiresAt"))
            val id = UUID.randomUUID().toString()
            p.put("id",id).put("role","joiner").put("session",qr.getString("session")).put("relay",relay)
                .put("peerKey",qr.getString("key")).put("peerLabel",qr.getString("label")).put("manual",manual)
                .put("invitation",invitation).put("invitationHash",qr.getString("hash"))
                .put("verificationMethod",verificationMethod)
            save()
            DurableAdmission.createJoiner(context,id,qr.getString("key")).use { it.joinerStart(invitation,System.currentTimeMillis() / 1000) }
        } else {
            require(p.getString("role") == "owner" && qr.getString("type") == "request" && p.getString("session") == qr.getString("session"))
            val request = PrototypeProtocol.exchange(relay,p.getString("session"),"request") ?: error("Request missing; ask your contact to retry")
            require(PrototypeProtocol.hash(request) == qr.getString("hash"))
            val native = JSONObject(PrototypeProtocol.decode(request).toString(Charsets.UTF_8))
            require(native.getString("devicePublicKey") == qr.getString("key") && native.getLong("expiresAt") == qr.getLong("expiresAt"))
            p.put("peerKey",qr.getString("key")).put("peerLabel",qr.getString("label")).put("manual",manual).put("requestHash",qr.getString("hash"))
                .put("verificationMethod",verificationMethod)
            save()
            vault().use { it.ownerAdmit(request,qr.getString("key"),true,System.currentTimeMillis() / 1000) }
        }
        if (verificationMethod == "bluetooth" && p.getString("role") == "joiner") {
            vault().use { PrototypeProtocol.exchange(relay,p.getString("session"),"request",it.resume().outbox) }
            return view()
        }
        return refresh()
    }
    fun refresh(): JSONObject {
        val p = profile ?: return view()
        if (!p.has("id")) return view()
        vault().use { admission ->
            val result = initialOutbox(admission)
            when(result.kind) {
                "invitation" -> {
                    p.put("invitationHash",PrototypeProtocol.hash(result.outbox)); save()
                    PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"invitation",result.outbox)
                }
                "request" -> {
                    p.put("requestHash",PrototypeProtocol.hash(result.outbox)); save()
                    PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"request",result.outbox)
                    val welcome = PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"welcome")
                    if (welcome != null) {
                        p.put("welcomeHash",PrototypeProtocol.hash(welcome)); save()
                        admission.joinerFinish(welcome,System.currentTimeMillis() / 1000)
                        publishReceipt(admission)
                    }
                }
                "welcome" -> {
                    p.put("welcomeHash",PrototypeProtocol.hash(result.outbox)); save()
                    PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"welcome",result.outbox)
                    val receipt = PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"receipt")
                    if (receipt != null) { PrototypeProtocol.verifyReceipt(p,receipt); p.put("confirmed",true); save() }
                }
                "joined" -> publishReceipt(admission)
                else -> error("Unsupported admission phase")
            }
        }
        return view()
    }
    private fun publishReceipt(admission: DurableAdmission) {
        val p = profile!!
        check(admission.resume().kind == "joined")
        if (!p.has("receipt")) { p.put("receipt",PrototypeProtocol.createReceipt(p)); save() }
        PrototypeProtocol.exchange(p.getString("relay"),p.getString("session"),"receipt",p.getString("receipt"))
    }
    fun acknowledge(): JSONObject {
        vault().use { admission -> admission.pending().forEach { message -> try { admission.acknowledge(message.id) } finally { message.clear() } } }
        return view()
    }
    fun reset(): JSONObject { store.reset(); profile = null; return view() }
    fun view(): JSONObject {
        val p = profile ?: return JSONObject().put("screen","profile")
        val result = JSONObject().put("nickname",p.getString("nickname")).put("avatar",p.getInt("avatar")).put("relay",p.getString("relay"))
        if (!p.has("id")) return result.put("screen","home")
        vault().use { admission ->
            val public = initialOutbox(admission)
            result.put("screen",public.kind).put("peerLabel",p.optString("peerLabel")).put("manual",p.optBoolean("manual"))
                .put("verificationMethod",p.optString("verificationMethod",if (p.optBoolean("manual")) "manual" else "qr"))
                .put("confirmed",p.optBoolean("confirmed")).put("fingerprint",PrototypeProtocol.digest(PrototypeProtocol.decode(public.nativePublicKey)))
            if (p.has("peerKey")) result.put("peerFingerprint",PrototypeProtocol.digest(PrototypeProtocol.decode(p.getString("peerKey"))))
            if (public.kind in setOf("invitation","request")) {
                val envelope = JSONObject(PrototypeProtocol.decode(public.outbox).toString(Charsets.UTF_8))
                val qr = JSONObject().put("v",1).put("type",if (public.kind == "invitation") "invite" else "request")
                    .put("relay",p.getString("relay")).put("session",p.getString("session")).put("key",public.nativePublicKey)
                    .put("hash",PrototypeProtocol.hash(public.outbox)).put("expiresAt",envelope.getLong("expiresAt")).put("label",p.getString("nickname"))
                result.put("qr",PrototypeProtocol.qr(qr)).put("expiresAt",envelope.getLong("expiresAt"))
            }
            if (public.kind == "joined") {
                val pending = admission.pending()
                result.put("pending",pending.size)
                pending.forEach { it.clear() }
            }
        }
        return result
    }
}
