package main

import "testing"

func TestCompatibleDatabaseRevisions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{name: "default", want: []string{"047"}},
		{name: "rollout window", value: "046, 047", want: []string{"046", "047"}},
		{name: "duplicate", value: "047,047", wantErr: true},
		{name: "malformed", value: "head", wantErr: true},
		{name: "unsupported", value: "047,048", wantErr: true},
		{name: "too broad", value: "045,046,047", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Setenv("AUTHCLAW_EXPECTED_DB_REVISION", "")
			} else {
				t.Setenv("AUTHCLAW_EXPECTED_DB_REVISION", tc.value)
			}
			got, err := compatibleDatabaseRevisions()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("compatibleDatabaseRevisions: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for index := range got {
				if got[index] != tc.want[index] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
