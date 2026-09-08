package main

import (
	"bytes"
	"encoding/json"
)

// Overlay normalized text onto the original document. Provider options and
// non-text content are outside the narrow inspection structs and must survive
// redaction, including integers too large for a float64.
func marshalRebuiltProviderRequest(original []byte, rebuilt interface{}) ([]byte, error) {
	updated, err := json.Marshal(rebuilt)
	if err != nil {
		return nil, err
	}
	decode := func(raw []byte) (interface{}, error) {
		var value interface{}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err := decoder.Decode(&value)
		return value, err
	}
	base, err := decode(original)
	if err != nil {
		return nil, err
	}
	patch, err := decode(updated)
	if err != nil {
		return nil, err
	}
	var overlay func(interface{}, interface{}) interface{}
	overlay = func(base, patch interface{}) interface{} {
		switch value := base.(type) {
		case map[string]interface{}:
			if changes, ok := patch.(map[string]interface{}); ok {
				for key, originalValue := range value {
					if replacement, exists := changes[key]; exists {
						value[key] = overlay(originalValue, replacement)
					}
				}
			}
		case []interface{}:
			if changes, ok := patch.([]interface{}); ok {
				for index := range value {
					if index < len(changes) {
						value[index] = overlay(value[index], changes[index])
					}
				}
			}
		case string:
			if replacement, ok := patch.(string); ok {
				return replacement
			}
		}
		return base
	}
	return json.Marshal(overlay(base, patch))
}
