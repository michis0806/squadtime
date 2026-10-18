package dev.squadtime.prototype

/** Unsaved entries stay in memory, separate from the encrypted committed profile. */
data class ProfileDraft(val nickname: String, val relay: String, val avatar: Int)

data class ProfileFormErrors(val nickname: String? = null, val relay: String? = null) {
    val hasErrors: Boolean get() = nickname != null || relay != null
}

class ProfileForm {
    private var draft: ProfileDraft? = null
    fun display(saved: ProfileDraft): ProfileDraft = draft ?: saved.also { draft = it }
    fun edit(value: ProfileDraft) { draft = value }
    fun current(): ProfileDraft = checkNotNull(draft)
    fun committed() { draft = null }
    fun validate(requireRelay: Boolean = false): ProfileFormErrors {
        val value = current()
        val nicknameError = when {
            value.nickname.isBlank() -> "Enter a test nickname."
            !PrototypeProtocol.validLabel(value.nickname) -> "Use at most 32 characters without control characters."
            else -> null
        }
        val relayError = when {
            value.relay.isEmpty() -> if (requireRelay) "Enter the local test relay before showing your code." else null
            runCatching { PrototypeProtocol.origin(value.relay) }.isFailure -> "Use http:// and a private IPv4 address, with no spaces, trailing slash or path. An explicit port must be 1024–65535."
            else -> null
        }
        return ProfileFormErrors(nicknameError,relayError)
    }
}
