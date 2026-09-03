package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func providerResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestProtectProviderErrorResponseProtectsJSONAndText(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/problem+json", "text/plain; charset=utf-8"} {
		t.Run(contentType, func(t *testing.T) {
			resp := providerResponse(http.StatusBadRequest, contentType, `provider leaked alice@example.com`)
			err := protectProviderErrorResponse(resp, 1024, func(body []byte) ([]byte, error) {
				return []byte(strings.ReplaceAll(string(body), "alice@example.com", "[REDACTED]")), nil
			})
			if err != nil {
				t.Fatalf("protect response: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "alice@example.com") || !strings.Contains(string(body), "[REDACTED]") {
				t.Fatalf("unprotected body: %s", body)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status changed to %d", resp.StatusCode)
			}
		})
	}
}

func TestProtectProviderErrorResponseUsesGenericBodyOnInspectionFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		body      string
		maxBytes  int64
		protector providerErrorBodyProtector
	}{
		"oversized": {body: strings.Repeat("x", 12), maxBytes: 4, protector: func(body []byte) ([]byte, error) { return body, nil }},
		"failure":   {body: "provider detail", maxBytes: 1024, protector: func([]byte) ([]byte, error) { return nil, errors.New("inspection unavailable") }},
	} {
		t.Run(name, func(t *testing.T) {
			resp := providerResponse(http.StatusServiceUnavailable, "text/plain", tc.body)
			if err := protectProviderErrorResponse(resp, tc.maxBytes, tc.protector); err != nil {
				t.Fatalf("protect response: %v", err)
			}
			protected, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(protected), "provider detail") || string(protected) != `{"error":"ProviderError","message":"Provider request failed."}` {
				t.Fatalf("unexpected generic body: %s", protected)
			}
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status changed to %d", resp.StatusCode)
			}
		})
	}
}

func TestProtectProviderErrorResponseUsesGenericBodyForMalformedContentType(t *testing.T) {
	before := ResponseProtectionMetricsSnapshot()["authclaw_gateway_provider_error_generic_fallback_total"]
	resp := providerResponse(http.StatusBadRequest, `application/json; charset="`, `{"email":"alice@example.com"}`)
	if err := protectProviderErrorResponse(resp, 1024, func(body []byte) ([]byte, error) {
		return body, nil
	}); err != nil {
		t.Fatalf("protect response: %v", err)
	}
	protected, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(protected), "alice@example.com") || string(protected) != `{"error":"ProviderError","message":"Provider request failed."}` {
		t.Fatalf("unexpected generic body: %s", protected)
	}
	after := ResponseProtectionMetricsSnapshot()["authclaw_gateway_provider_error_generic_fallback_total"]
	if after != before+1 {
		t.Fatalf("generic fallback metric changed by %d, want 1", after-before)
	}
}

func TestProtectProviderErrorResponsePreservesBinaryAndStreamingBodies(t *testing.T) {
	for _, contentType := range []string{"application/octet-stream", "text/event-stream"} {
		resp := providerResponse(http.StatusBadGateway, contentType, "unchanged")
		called := false
		if err := protectProviderErrorResponse(resp, 1024, func(body []byte) ([]byte, error) {
			called = true
			return body, nil
		}); err != nil {
			t.Fatalf("protect response: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if called || string(body) != "unchanged" {
			t.Fatalf("%s body should be preserved", contentType)
		}
	}
}
