package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIRequest represents a standard OpenAI Chat Completion request body
type OpenAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// AnthropicRequest represents a standard Anthropic Messages request body
type AnthropicRequest struct {
	Model    string    `json:"model"`
	System   string    `json:"system,omitempty"`
	Messages []Message `json:"messages"`
}

func normalizeAnthropicRequest(normalized *NormalizedRequest, req *AnthropicRequest, original []byte) func([]string) ([]byte, error) {
	normalized.Model = req.Model
	if req.System != "" {
		normalized.Prompts = append(normalized.Prompts, req.System)
	}
	for _, msg := range req.Messages {
		normalized.Prompts = append(normalized.Prompts, msg.Content)
	}
	return func(newPrompts []string) ([]byte, error) {
		idx := 0
		if req.System != "" && idx < len(newPrompts) {
			req.System = newPrompts[idx]
			idx++
		}
		for i := range req.Messages {
			if idx < len(newPrompts) {
				req.Messages[i].Content = newPrompts[idx]
				idx++
			}
		}
		return marshalRebuiltProviderRequest(original, req)
	}
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

// GeminiRequest represents a standard Gemini request body
type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

func extractAzureDeploymentModel(path string) string {
	parts := strings.Split(path, "/deployments/")
	if len(parts) <= 1 {
		return ""
	}
	subParts := strings.Split(parts[1], "/")
	return subParts[0]
}

func extractGeminiModel(path string) string {
	parts := strings.Split(path, "/models/")
	if len(parts) > 1 {
		subParts := strings.Split(parts[1], ":")
		return subParts[0]
	}
	return ""
}

// NormalizedRequest is the gateway's internal standard format
type NormalizedRequest struct {
	Provider string
	Model    string
	Prompts  []string // Extracted text content to redact/evaluate
}

// ExtractAndNormalize parses the request body and returns a NormalizedRequest
// and a helper function to rebuild the request body with modified prompts
func ExtractAndNormalize(r *http.Request, provider string) (*NormalizedRequest, func([]string) ([]byte, error), error) {
	// Read original body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}
	// Restore body for downstream proxying
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	normalized := &NormalizedRequest{
		Provider: provider,
	}

	switch provider {
	case "openai", "azure_openai":
		var openAIReq OpenAIRequest
		if err := json.Unmarshal(bodyBytes, &openAIReq); err != nil {
			return nil, nil, err
		}
		normalized.Model = openAIReq.Model
		if normalized.Model == "" && provider == "azure_openai" {
			normalized.Model = extractAzureDeploymentModel(r.URL.Path)
		}
		for _, msg := range openAIReq.Messages {
			normalized.Prompts = append(normalized.Prompts, msg.Content)
		}

		rebuilder := func(newPrompts []string) ([]byte, error) {
			for i, p := range newPrompts {
				if i < len(openAIReq.Messages) {
					openAIReq.Messages[i].Content = p
				}
			}
			return marshalRebuiltProviderRequest(bodyBytes, openAIReq)
		}
		return normalized, rebuilder, nil

	case "anthropic":
		var anthropicReq AnthropicRequest
		if err := json.Unmarshal(bodyBytes, &anthropicReq); err != nil {
			return nil, nil, err
		}
		return normalized, normalizeAnthropicRequest(normalized, &anthropicReq, bodyBytes), nil

	case "cohere":
		var cohereReq map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &cohereReq); err != nil {
			return nil, nil, err
		}
		if model, ok := cohereReq["model"].(string); ok {
			normalized.Model = model
		}

		type cohereTextRef struct {
			container map[string]interface{}
			key       string
		}
		refs := []cohereTextRef{}
		appendStringRef := func(container map[string]interface{}, key string) {
			if value, ok := container[key].(string); ok && value != "" {
				normalized.Prompts = append(normalized.Prompts, value)
				refs = append(refs, cohereTextRef{container: container, key: key})
			}
		}

		if messages, ok := cohereReq["messages"].([]interface{}); ok {
			for _, rawMessage := range messages {
				message, ok := rawMessage.(map[string]interface{})
				if !ok {
					continue
				}
				appendStringRef(message, "content")
				if blocks, ok := message["content"].([]interface{}); ok {
					for _, rawBlock := range blocks {
						block, ok := rawBlock.(map[string]interface{})
						if !ok {
							continue
						}
						appendStringRef(block, "text")
					}
				}
			}
		}
		appendStringRef(cohereReq, "message")
		appendStringRef(cohereReq, "prompt")
		if history, ok := cohereReq["chat_history"].([]interface{}); ok {
			for _, rawItem := range history {
				item, ok := rawItem.(map[string]interface{})
				if !ok {
					continue
				}
				appendStringRef(item, "message")
			}
		}
		if texts, ok := cohereReq["texts"].([]interface{}); ok {
			for idx, rawText := range texts {
				text, ok := rawText.(string)
				if !ok || text == "" {
					continue
				}
				normalized.Prompts = append(normalized.Prompts, text)
				index := idx
				refs = append(refs, cohereTextRef{
					container: map[string]interface{}{"__texts_index": index},
					key:       "texts",
				})
			}
		}

		rebuilder := func(newPrompts []string) ([]byte, error) {
			for i, ref := range refs {
				if i >= len(newPrompts) {
					break
				}
				if ref.key == "texts" {
					index, _ := ref.container["__texts_index"].(int)
					if texts, ok := cohereReq["texts"].([]interface{}); ok && index < len(texts) {
						texts[index] = newPrompts[i]
					}
					continue
				}
				ref.container[ref.key] = newPrompts[i]
			}
			return json.Marshal(cohereReq)
		}
		return normalized, rebuilder, nil

	case "gemini":
		var geminiReq GeminiRequest
		if err := json.Unmarshal(bodyBytes, &geminiReq); err != nil {
			return nil, nil, err
		}
		normalized.Model = extractGeminiModel(r.URL.Path)
		for _, content := range geminiReq.Contents {
			for _, part := range content.Parts {
				if part.Text != "" {
					normalized.Prompts = append(normalized.Prompts, part.Text)
				}
			}
		}

		rebuilder := func(newPrompts []string) ([]byte, error) {
			idx := 0
			for i := range geminiReq.Contents {
				for j := range geminiReq.Contents[i].Parts {
					if geminiReq.Contents[i].Parts[j].Text != "" && idx < len(newPrompts) {
						geminiReq.Contents[i].Parts[j].Text = newPrompts[idx]
						idx++
					}
				}
			}
			return marshalRebuiltProviderRequest(bodyBytes, geminiReq)
		}
		return normalized, rebuilder, nil
	case "bedrock":
		return normalizeBedrockRequest(r.URL.Path, bodyBytes)

	default:
		// Non-parsed or passthrough
		rebuilder := func(newPrompts []string) ([]byte, error) {
			return bodyBytes, nil
		}
		return normalized, rebuilder, nil
	}
}

// Bedrock is text-only until every additional content schema can be inspected.
// Keep raw JSON values so provider options retain their original numeric precision.
func normalizeBedrockRequest(path string, body []byte) (*NormalizedRequest, func([]string) ([]byte, error), error) {
	model := ExtractBedrockModel(path)
	invalid := fmt.Errorf("unsupported or malformed Bedrock text request")
	if model == "" || strings.TrimPrefix(path, "/bedrock") != "/model/"+model+"/invoke" {
		return nil, nil, invalid
	}
	var document map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, nil, invalid
	}
	var extra interface{}
	if decoder.Decode(&extra) != io.EOF {
		return nil, nil, invalid
	}
	normalized := &NormalizedRequest{Provider: ProviderBedrock, Model: model}
	var setters []func(string)
	validKeys := func(object map[string]interface{}, allowed ...string) bool {
		keys := make(map[string]bool, len(allowed))
		for _, key := range allowed {
			keys[key] = true
		}
		for key := range object {
			if !keys[key] {
				return false
			}
		}
		return true
	}
	text := func(object map[string]interface{}, key string) bool {
		value, ok := object[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
		normalized.Prompts = append(normalized.Prompts, value)
		setters = append(setters, func(value string) { object[key] = value })
		return true
	}
	texts := func(object map[string]interface{}, key string) bool {
		if _, exists := object[key]; !exists {
			return true
		}
		values, ok := object[key].([]interface{})
		if !ok {
			return false
		}
		for i, raw := range values {
			value, ok := raw.(string)
			if !ok || value == "" {
				return false
			}
			normalized.Prompts = append(normalized.Prompts, value)
			index := i
			setters = append(setters, func(value string) { values[index] = value })
		}
		return true
	}
	content := func(object map[string]interface{}, key string) bool {
		if _, ok := object[key].(string); ok {
			return text(object, key)
		}
		blocks, ok := object[key].([]interface{})
		if !ok || len(blocks) == 0 {
			return false
		}
		for _, raw := range blocks {
			block, ok := raw.(map[string]interface{})
			if !ok || block["type"] != "text" || !validKeys(block, "type", "text") || !text(block, "text") {
				return false
			}
		}
		return true
	}
	positiveInteger := func(object map[string]interface{}, key string) bool {
		value, ok := object[key].(json.Number)
		if !ok {
			return false
		}
		number, err := value.Int64()
		return err == nil && number > 0
	}
	numericOptions := func(object map[string]interface{}, keys ...string) bool {
		for _, key := range keys {
			if value, exists := object[key]; exists {
				if _, ok := value.(json.Number); !ok {
					return false
				}
			}
		}
		return true
	}
	family := model
	for _, prefix := range []string{"us.", "eu.", "apac.", "global."} {
		family = strings.TrimPrefix(family, prefix)
	}
	switch {
	case strings.HasPrefix(family, "anthropic.claude-"):
		if !validKeys(document, "anthropic_version", "max_tokens", "system", "messages", "temperature", "top_p", "top_k", "stop_sequences") ||
			document["anthropic_version"] != "bedrock-2023-05-31" || !positiveInteger(document, "max_tokens") || !numericOptions(document, "temperature", "top_p", "top_k") {
			return nil, nil, invalid
		}
		if _, exists := document["system"]; exists && !content(document, "system") {
			return nil, nil, invalid
		}
		messages, ok := document["messages"].([]interface{})
		if !ok || len(messages) == 0 {
			return nil, nil, invalid
		}
		for _, raw := range messages {
			message, ok := raw.(map[string]interface{})
			if !ok || !validKeys(message, "role", "content") || (message["role"] != "user" && message["role"] != "assistant") || !content(message, "content") {
				return nil, nil, invalid
			}
		}
		if !texts(document, "stop_sequences") {
			return nil, nil, invalid
		}
	case strings.HasPrefix(family, "amazon.titan-text-"):
		config, ok := document["textGenerationConfig"].(map[string]interface{})
		if !ok || !validKeys(document, "inputText", "textGenerationConfig") || !validKeys(config, "maxTokenCount", "stopSequences", "temperature", "topP") ||
			!positiveInteger(config, "maxTokenCount") || !numericOptions(config, "temperature", "topP") || !text(document, "inputText") || !texts(config, "stopSequences") {
			return nil, nil, invalid
		}
	default:
		return nil, nil, invalid
	}
	return normalized, func(prompts []string) ([]byte, error) {
		if len(prompts) != len(setters) {
			return nil, fmt.Errorf("prompt replacement count mismatch")
		}
		for i, set := range setters {
			set(prompts[i])
		}
		return json.Marshal(document)
	}, nil
}
