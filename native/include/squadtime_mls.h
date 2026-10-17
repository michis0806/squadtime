#ifndef SQUADTIME_MLS_H
#define SQUADTIME_MLS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Development-only, synthetic MLS proof. All buffers are SECRET; never log.
 * UTF-8 JSON; standard padded Base64 values. Maximum input/output: 16 MiB.
 * {"op":"fixture"} -> {"snapshot":str,"packets":[str,str],"expected":[str,str]}
 * {"op":"enrollmentprepare","devicePublicKey":b64SEC1,
 *  "approverPublicKey":b64SEC1,"now":uint53}
 *   -> {"pendingId":b64,"groupId":b64,"keyPackage":b64,
 *       "request":b64UTF8,"approval":b64UTF8}
 * {"op":"enrollmentcomplete","pendingId":b64,"groupId":b64,
 *  "keyPackage":b64,"requestSignature":b64DER,"approvalSignature":b64DER,
 *  "now":uint53} -> same reply shape as fixture.
 * {"op":"enrollmentcancel","pendingId":b64} -> {"cancelled":true}
 * Enrollment is a LOCAL single-process proof: trusted native P256 key inputs,
 * process-local pending secrets, maximum 16 contexts, 300-second lifetime.
 * Rejected context/signatures preserve pending; success/cancel consumes it.
 * Expired contexts are cleared on prepare/complete. No restart/outbox promise.
 * DER is canonical ECDSA P256 (8..72 bytes); high-S is allowed.
 * {"op":"receive","snapshot":str,"packet":str}
 *   -> {"snapshot":str,"plaintext":str,"senderIndex":uint32}
 * snapshot is trusted LOCAL secret state, never a server/network input.
 * Receive returns a staged state only. Native code must atomically CAS-commit
 * new encrypted snapshot + encrypted inbox before acknowledging/displaying.
 * Status 0=success, 1=generic rejection, 2=invalid ABI arguments.
 * On failure *output=NULL, *output_len=0 (when output arguments are valid).
 * Input must be readable; outputs must be writable, aligned, distinct and must
 * not alias input. Successful output is not NUL terminated. Copy then free once
 * with the EXACT returned pointer and length. No concurrent access to buffers.
 */
int32_t squadtime_mls_call(const uint8_t *input, size_t input_len,
                         uint8_t **output, size_t *output_len);
/* Zeroizes the returned allocation before releasing it. NULL/0 is a no-op.
 * Any non-NULL pointer MUST be a live bridge allocation with its exact length.
 */
void squadtime_mls_free(uint8_t *output, size_t output_len);
#ifdef __cplusplus
}
#endif
#endif
