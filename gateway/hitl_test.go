package main

import (
	"testing"
	"time"
)

func TestHITLTimeoutUsesSRSCompatibleThirtyMinuteWindow(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{name: "default is thirty minutes", seconds: 0, want: 30 * time.Minute},
		{name: "explicit thirty minutes is accepted", seconds: 1800, want: 30 * time.Minute},
		{name: "higher values cap at thirty minutes", seconds: 3600, want: 30 * time.Minute},
		{name: "lower values floor at ten seconds", seconds: 3, want: 10 * time.Second},
		{name: "custom value inside range is preserved", seconds: 900, want: 15 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hitlTimeout(RegexRule{HITLTimeoutSeconds: tt.seconds})
			if got != tt.want {
				t.Fatalf("hitlTimeout(%d) = %s, want %s", tt.seconds, got, tt.want)
			}
		})
	}
}
