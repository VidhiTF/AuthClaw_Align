package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteGatewayErrorEncodesUntrustedMessageAsJSON(t *testing.T) {
	message := "policy said \"deny\"\nnext:\t雪"
	recorder := httptest.NewRecorder()

	writeGatewayError(recorder, http.StatusForbidden, "PolicyBlocked", message)

	response := recorder.Result()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", contentType)
	}
	var payload gatewayErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "PolicyBlocked" || payload.Message != message {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestWriteJSONEncodesOptionalErrorFields(t *testing.T) {
	recorder := httptest.NewRecorder()
	payload := gatewayErrorResponse{
		Error:      "ApprovalRequired",
		Message:    "status is \"DENIED\"\r\n",
		Provider:   "openai\ninvalid",
		ApprovalID: "approval-\"quoted\"",
	}

	writeJSON(recorder, http.StatusForbidden, payload)

	var decoded gatewayErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded != payload {
		t.Fatalf("decoded payload = %#v, want %#v", decoded, payload)
	}
}
