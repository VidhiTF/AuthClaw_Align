package main

import (
	"strings"
	"testing"
)

func TestSecretRetirementPythonEnvelopeCompatibility(t *testing.T) {
	t.Setenv("AUTHCLAW_SECRET_PROVIDER", "env")
	t.Setenv("AUTHCLAW_SECRET_KEY_VERSION", "v7")
	t.Setenv("ENVELOPE_KEY_V7", "test-envelope-key-material-32-bytes!!")
	t.Setenv("ENVELOPE_KEY", "test-envelope-key-material-32-bytes!!")
	t.Setenv("ENCRYPTION_KEY", "")
	encryptionKey = nil
	defer func() { encryptionKey = nil }()
	const vector = "authclaw-secret-v2:env:v7:AAECAwQFBgcICQoLfg77cQzhaxHPBVah3UEx1MbA1dIqCVyxukG74cXQlchpvK/oTDA="
	for _, encoded := range []string{vector, strings.Replace(vector, "authclaw-secret-v2:env:v7:", "authclaw-secret-v1:", 1)} {
		got, err := DecryptSecret(encoded)
		if err != nil || got != "shared-provider-secret" {
			t.Fatalf("Python AES-GCM vector failed: %v", err)
		}
	}
}

func TestSecretRetirementRejectsLegacyAndCorruptFormats(t *testing.T) {
	for _, encoded := range []string{"", "unknown:payload", "authclaw-secret-v2::v1:AAAA", "authclaw-secret-v2:env::AAAA", "authclaw-secret-v2:env:v1:!invalid!", "authclaw-secret-v1:AAAA"} {
		if _, err := DecryptSecret(encoded); err == nil {
			t.Fatalf("accepted invalid format %q", encoded)
		}
	}
}
