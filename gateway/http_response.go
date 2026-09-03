package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type gatewayErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	Provider   string `json:"provider,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[HTTP] status=json_encode_failed response_status=%d err=%v", status, err)
	}
}

func writeGatewayError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, gatewayErrorResponse{Error: code, Message: message})
}
