package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"unsafe"

	"requests-utls/native"
)

func TestABIRejectsNullAndOversizedInput(t *testing.T) {
	if got := ruts_abi_version(); got != 1 {
		t.Fatal(got)
	}
	results := []struct {
		name  string
		value native.Result
	}{}
	// Exercise the actual exported entry points, including their input guards.
	null := ruts_session_create(nil, 1)
	large := ruts_session_create(nil, native.MaxMetadataBytes+1)
	body := ruts_request_submit(0, nil, 0, nil, native.MaxRequestBytes+1)
	opaque := ruts_profile_import(nil, 0, 2)
	for _, value := range []struct {
		name string
		code int32
		data unsafe.Pointer
		size int
	}{
		{"null", int32(null.code), unsafe.Pointer(null.data), int(null.length)},
		{"metadata limit", int32(large.code), unsafe.Pointer(large.data), int(large.length)},
		{"body limit", int32(body.code), unsafe.Pointer(body.data), int(body.length)},
		{"opaque flag", int32(opaque.code), unsafe.Pointer(opaque.data), int(opaque.length)},
	} {
		results = append(results, struct {
			name  string
			value native.Result
		}{value.name, native.Result{Code: value.code, Data: bytes.Clone(unsafe.Slice((*byte)(value.data), value.size))}})
		ruts_buffer_free(value.data)
	}
	for _, item := range results {
		if item.value.Code != native.InvalidInput || !json.Valid(item.value.Data) {
			t.Errorf("%s: %+v", item.name, item.value)
		}
	}
	ruts_buffer_free(nil)
}

func TestCResultBufferHasIndependentOwnership(t *testing.T) {
	input := []byte{0, 1, 255, 2}
	value := result(native.Result{Code: native.OK, Handle: 42, Data: input})
	defer ruts_buffer_free(unsafe.Pointer(value.data))
	input[0] = 99
	got := unsafe.Slice((*byte)(unsafe.Pointer(value.data)), int(value.length))
	if value.handle != 42 || !bytes.Equal(got, []byte{0, 1, 255, 2}) {
		t.Fatalf("invalid C-owned result: handle=%d data=%v", value.handle, got)
	}
}
