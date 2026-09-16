package main

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityNormalizationTextCoverage(t *testing.T) {
	for _, tc := range []struct {
		provider, path, body, model string
		prompts                     []string
	}{
		{"bedrock", "/bedrock/model/anthropic.claude-3-sonnet/invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,"system":"system secret","messages":[{"role":"user","content":[{"type":"text","text":"user secret"}]}]}`, "anthropic.claude-3-sonnet", []string{"system secret", "user secret"}},
		{"bedrock", "/bedrock/model/us.anthropic.claude-3-sonnet/invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,"system":[{"type":"text","text":"system secret"}],"messages":[{"role":"user","content":"user secret"}],"stop_sequences":["stop secret"]}`, "us.anthropic.claude-3-sonnet", []string{"system secret", "user secret", "stop secret"}},
		{"bedrock", "/bedrock/model/amazon.titan-text-express-v1/invoke", `{"inputText":"user secret","textGenerationConfig":{"maxTokenCount":64,"stopSequences":["stop secret"]}}`, "amazon.titan-text-express-v1", []string{"user secret", "stop secret"}},
	} {
		t.Run(tc.provider+tc.model, func(t *testing.T) {
			n, rebuild, err := ExtractAndNormalize(httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body)), tc.provider)
			if err != nil {
				t.Fatal(err)
			}
			if n.Model != tc.model || !reflect.DeepEqual(n.Prompts, tc.prompts) {
				t.Fatalf("wrong normalization: %#v", n)
			}
			replacement := make([]string, len(n.Prompts))
			for i := range replacement {
				replacement[i] = "REDACTED"
			}
			body, err := rebuild(replacement)
			if err != nil || strings.Contains(string(body), "secret") || !json.Valid(body) {
				t.Fatalf("unsafe rebuilt body %s: %v", body, err)
			}

			if _, err := rebuild(nil); err == nil {
				t.Fatal("missing replacements accepted")
			}
		})
	}
}

func TestSecurityBedrockRejectsUninspectablePayload(t *testing.T) {
	for _, tc := range []struct{ model, body string }{
		{"anthropic.claude-3-sonnet", `{"messages":[{"role":"user","content":[{"type":"image","source":{"data":"secret"}}]}]}`},
		{"anthropic.claude-3-sonnet", `{"messages":[{"role":"user","content":"hi"}],"tools":[{"description":"secret"}]}`},
		{"anthropic.claude-3-sonnet", `{"messages":[]}`},
		{"anthropic.claude-3-sonnet", `{"prompt":"secret"}`},
		{"amazon.titan-text-express-v1", `{"inputText":null}`},
		{"amazon.titan-text-express-v1", `{"inputText":"hi","unexpected":"secret"}`},
		{"meta.llama3-8b-instruct-v1", `{"prompt":"secret"}`},
		{"anthropic.claude-3-sonnet", `{"messages":`},
	} {
		t.Run(tc.model+tc.body, func(t *testing.T) {
			// Supply valid required options so each case reaches the content-schema check.
			if strings.HasPrefix(tc.model, "anthropic.") && json.Valid([]byte(tc.body)) {
				tc.body = `{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,` + strings.TrimPrefix(tc.body, "{")
			}
			if strings.HasPrefix(tc.model, "amazon.") {
				tc.body = `{"textGenerationConfig":{"maxTokenCount":64},` + strings.TrimPrefix(tc.body, "{")
			}
			_, _, err := ExtractAndNormalize(httptest.NewRequest("POST", "/bedrock/model/"+tc.model+"/invoke", strings.NewReader(tc.body)), "bedrock")
			if err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}

func TestSecurityBedrockRequiresBoundedInvocation(t *testing.T) {
	for _, tc := range []struct{ path, body string }{
		{"/bedrock/model/anthropic.claude-3-sonnet/invoke-with-response-stream", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`},
		{"/bedrock/model/anthropic.claude-3-sonnet/invoke", `{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"hi"}]}`},
		{"/bedrock/model/anthropic.claude-3-sonnet/invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":1.5,"messages":[{"role":"user","content":"hi"}]}`},
		{"/bedrock/model/amazon.titan-text-express-v1/invoke", `{"inputText":"hi"}`},
		{"/bedrock/model/amazon.titan-text-express-v1/invoke", `{"inputText":"hi","textGenerationConfig":{"maxTokenCount":0}}`},
		{"/bedrock/model/amazon.titan-text-express-v1/invoke", `{"inputText":"hi","textGenerationConfig":{"maxTokenCount":64}} {}`},
	} {
		_, _, err := ExtractAndNormalize(httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body)), "bedrock")
		if err == nil {
			t.Fatalf("unbounded/unsupported invocation accepted: %s %s", tc.path, tc.body)
		}
	}
}
