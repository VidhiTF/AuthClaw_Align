package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

const defaultProviderErrorInspectionBytes = 256 * 1024

type providerErrorBodyProtector func([]byte) ([]byte, error)

var (
	providerErrorGenericFallbackTotal atomic.Uint64
	providerErrorJSON4xxTotal         atomic.Uint64
	providerErrorJSON5xxTotal         atomic.Uint64
	providerErrorText4xxTotal         atomic.Uint64
	providerErrorText5xxTotal         atomic.Uint64
)

func recordProtectedProviderError(status int, contentType string) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	isJSON := mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
	is4xx := status >= http.StatusBadRequest && status < http.StatusInternalServerError
	switch {
	case isJSON && is4xx:
		providerErrorJSON4xxTotal.Add(1)
	case isJSON:
		providerErrorJSON5xxTotal.Add(1)
	case is4xx:
		providerErrorText4xxTotal.Add(1)
	default:
		providerErrorText5xxTotal.Add(1)
	}
}

func ResponseProtectionMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_provider_error_generic_fallback_total": providerErrorGenericFallbackTotal.Load(),
		"authclaw_gateway_provider_error_json_4xx_total":         providerErrorJSON4xxTotal.Load(),
		"authclaw_gateway_provider_error_json_5xx_total":         providerErrorJSON5xxTotal.Load(),
		"authclaw_gateway_provider_error_text_4xx_total":         providerErrorText4xxTotal.Load(),
		"authclaw_gateway_provider_error_text_5xx_total":         providerErrorText5xxTotal.Load(),
	}
}

func isInspectableProviderErrorContentType(value string) (bool, error) {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false, err
	}
	mediaType = strings.ToLower(mediaType)
	if mediaType == "text/event-stream" {
		return false, nil
	}
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"), nil
}

func setProviderResponseBody(resp *http.Response, body []byte, contentType string) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Del("Content-Encoding")
}

func replaceWithGenericProviderError(resp *http.Response) error {
	body, err := json.Marshal(gatewayErrorResponse{
		Error:   "ProviderError",
		Message: "Provider request failed.",
	})
	if err != nil {
		return fmt.Errorf("encode generic provider error: %w", err)
	}
	setProviderResponseBody(resp, body, "application/json")
	providerErrorGenericFallbackTotal.Add(1)
	return nil
}

func protectProviderErrorResponse(
	resp *http.Response,
	maxBytes int64,
	protect providerErrorBodyProtector,
) error {
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	contentType := resp.Header.Get("Content-Type")
	inspectable, contentTypeErr := isInspectableProviderErrorContentType(contentType)
	if contentTypeErr != nil {
		return replaceWithGenericProviderError(resp)
	}
	if !inspectable {
		return nil
	}
	if maxBytes <= 0 {
		maxBytes = defaultProviderErrorInspectionBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	closeErr := resp.Body.Close()
	if err != nil || closeErr != nil || int64(len(body)) > maxBytes {
		return replaceWithGenericProviderError(resp)
	}
	protected, err := protect(body)
	if err != nil {
		return replaceWithGenericProviderError(resp)
	}
	setProviderResponseBody(resp, protected, contentType)
	recordProtectedProviderError(resp.StatusCode, contentType)
	return nil
}
