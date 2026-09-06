// Command requests-utls-shared builds ABI v1 with -buildmode=c-shared.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#define RUTS_TYPES_ONLY
#include "requests_utls.h"
#undef RUTS_TYPES_ONLY
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/chuu3/requests-utls/native"
)

var registry = native.NewRegistry()

func result(value native.Result) C.RUTS_Result {
	out := C.RUTS_Result{code: C.int32_t(value.Code), handle: C.uint64_t(value.Handle)}
	if len(value.Data) > 0 {
		memory := C.malloc(C.size_t(len(value.Data)))
		if memory == nil {
			out.code = C.int32_t(native.InternalError)
			return out
		}
		copy(unsafe.Slice((*byte)(memory), len(value.Data)), value.Data)
		out.data, out.length = (*C.uchar)(memory), C.size_t(len(value.Data))
	}
	return out
}

func recoverResult(out *C.RUTS_Result) {
	if recover() != nil {
		*out = result(native.Error(native.InternalError, "internal ABI panic"))
	}
}

func recoverCode(out *C.int32_t) {
	if recover() != nil {
		*out = C.int32_t(native.InternalError)
	}
}

func input(pointer *C.uchar, length C.size_t, limit uint64) ([]byte, error) {
	if uint64(length) > limit {
		return nil, errors.New("ABI input exceeds size limit")
	}
	if length == 0 {
		return nil, nil
	}
	if pointer == nil {
		return nil, errors.New("NULL input pointer with nonzero length")
	}
	return C.GoBytes(unsafe.Pointer(pointer), C.int(length)), nil
}

//export ruts_abi_version
func ruts_abi_version() C.uint32_t { return C.uint32_t(native.ABIVersion) }

//export ruts_session_create
func ruts_session_create(pointer *C.uchar, length C.size_t) (out C.RUTS_Result) {
	defer recoverResult(&out)
	data, err := input(pointer, length, native.MaxMetadataBytes)
	if err != nil {
		return result(native.Error(native.InvalidInput, err.Error()))
	}
	return result(registry.SessionCreate(data))
}

//export ruts_request_submit
func ruts_request_submit(session C.uint64_t, metadata *C.uchar, metadataLength C.size_t, body *C.uchar, bodyLength C.size_t) (out C.RUTS_Result) {
	defer recoverResult(&out)
	meta, err := input(metadata, metadataLength, native.MaxMetadataBytes)
	if err != nil {
		return result(native.Error(native.InvalidInput, err.Error()))
	}
	payload, err := input(body, bodyLength, native.MaxRequestBytes)
	if err != nil {
		return result(native.Error(native.InvalidInput, err.Error()))
	}
	return result(registry.RequestSubmit(uint64(session), meta, payload))
}

//export ruts_session_poll
func ruts_session_poll(session C.uint64_t, timeoutMS C.int32_t) (out C.RUTS_Result) {
	defer recoverResult(&out)
	return result(registry.SessionPoll(uint64(session), int32(timeoutMS)))
}

//export ruts_request_body
func ruts_request_body(request C.uint64_t) (out C.RUTS_Result) {
	defer recoverResult(&out)
	return result(registry.RequestBody(uint64(request)))
}

//export ruts_request_cancel
func ruts_request_cancel(request C.uint64_t) (out C.int32_t) {
	defer recoverCode(&out)
	return C.int32_t(registry.RequestCancel(uint64(request)))
}

//export ruts_request_release
func ruts_request_release(request C.uint64_t) (out C.int32_t) {
	defer recoverCode(&out)
	return C.int32_t(registry.RequestRelease(uint64(request)))
}

//export ruts_session_close
func ruts_session_close(session C.uint64_t) (out C.int32_t) {
	defer recoverCode(&out)
	return C.int32_t(registry.SessionClose(uint64(session)))
}

//export ruts_profile_import
func ruts_profile_import(pointer *C.uchar, length C.size_t, allowOpaque C.int32_t) (out C.RUTS_Result) {
	defer recoverResult(&out)
	if allowOpaque != 0 && allowOpaque != 1 {
		return result(native.Error(native.InvalidInput, "allow_opaque must be 0 or 1"))
	}
	data, err := input(pointer, length, native.MaxMetadataBytes)
	if err != nil {
		return result(native.Error(native.InvalidInput, err.Error()))
	}
	return result(native.ProfileImport(data, allowOpaque == 1))
}

//export ruts_buffer_free
func ruts_buffer_free(pointer unsafe.Pointer) { C.free(pointer) }

func main() {}
