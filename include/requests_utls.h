#ifndef REQUESTS_UTLS_H
#define REQUESTS_UTLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RUTS_Result {
    int32_t code;
    uint64_t handle;
    unsigned char *data;
    size_t length;
} RUTS_Result;

enum RUTS_Code {
    RUTS_OK = 0,
    RUTS_POLL_TIMEOUT = 1,
    RUTS_SESSION_CLOSED = 2,
    RUTS_INVALID_INPUT = 3,
    RUTS_INVALID_HANDLE = 4,
    RUTS_QUEUE_FULL = 5,
    RUTS_CANCELED = 6,
    RUTS_DEADLINE = 7,
    RUTS_RESPONSE_TOO_LARGE = 8,
    RUTS_TRANSPORT_ERROR = 9,
    RUTS_INTERNAL_ERROR = 10
};

/* Each non-NULL result.data is caller-owned; free exactly once. Inputs are
 * borrowed only during the call and never retained. No Go pointers escape. */
#ifndef RUTS_TYPES_ONLY
uint32_t ruts_abi_version(void);
RUTS_Result ruts_session_create(const unsigned char *json, size_t length);
RUTS_Result ruts_request_submit(uint64_t session, const unsigned char *metadata,
    size_t metadata_length, const unsigned char *body, size_t body_length);
/* -1 waits indefinitely, 0 checks immediately, >0 waits that many milliseconds. */
RUTS_Result ruts_session_poll(uint64_t session, int32_t timeout_ms);
RUTS_Result ruts_request_body(uint64_t request);
int32_t ruts_request_cancel(uint64_t request);
int32_t ruts_request_release(uint64_t request);
int32_t ruts_session_close(uint64_t session);
RUTS_Result ruts_profile_import(const unsigned char *json, size_t length,
    int32_t allow_opaque);
void ruts_buffer_free(void *buffer);
#endif

#ifdef __cplusplus
}
#endif
#endif
