package dev.squadtime.prototype

import org.junit.Assert.*
import org.junit.Test

class ProfileFormTest {
    @Test fun blankNicknamePreservesEnteredRelayUntilCorrectedAndCommitted() {
        val form = ProfileForm()
        val empty = ProfileDraft("","",0)
        form.display(empty)
        val entered = ProfileDraft("","http://192.168.33.2:8789",0)
        form.edit(entered)
        val errors = form.validate()
        assertEquals("Enter a test nickname.",errors.nickname)
        assertNull(errors.relay)
        assertEquals(entered,form.display(empty))
        val corrected = entered.copy(nickname = "Android-Test")
        form.edit(corrected)
        assertFalse(form.validate().hasErrors)
        form.committed()
        assertEquals(corrected,form.display(corrected))
    }
    @Test fun rerenderAfterStorageFailureKeepsRawEntriesInsteadOfSavedValues() {
        val form = ProfileForm()
        val saved = ProfileDraft("Old test","http://192.168.33.2:8789",0)
        form.display(saved)
        val edited = ProfileDraft("New test","http://192.168.33.3:8789",2)
        form.edit(edited)
        assertEquals(edited,form.display(saved))
        assertEquals(edited,form.current())
    }
    @Test fun showCodeUsesCurrentValidatedRelayAndRequiresAnAddress() {
        val form = ProfileForm()
        form.display(ProfileDraft("Android-Test","",0))
        assertFalse(form.validate().hasErrors)
        assertNotNull(form.validate(requireRelay = true).relay)
        form.edit(form.current().copy(relay = "http://192.168.33.4:8789"))
        assertFalse(form.validate(requireRelay = true).hasErrors)
        assertEquals("http://192.168.33.4:8789",form.current().relay)
    }
    @Test fun invalidOriginIsNotSilentlyTrimmedOrNormalized() {
        val form = ProfileForm()
        for (raw in listOf(" http://192.168.33.2:8789", "http://192.168.33.2:8789/", "https://192.168.33.2:8789", "http://example.com:8789")) {
            form.edit(ProfileDraft("Android-Test",raw,0))
            assertNotNull(form.validate().relay)
            assertEquals(raw,form.current().relay)
        }
    }
}
