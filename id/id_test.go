package id

import "testing"

// TestIsBlankMachineID verifies placeholder machine IDs written by systemd
// in containers and VMs are rejected: they are not unique, so they must
// never derive a signing key.
func TestIsBlankMachineID(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		blank bool
	}{
		{"real id", "3d6e2c41f0c94a8f9b1d77e2a0c4b5e6", false},
		{"uninitialized", "uninitialized", true},
		{"all zeros", "00000000000000000000000000000000", true},
		{"partial zeros", "0000000000000000000000000abc0000", false},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBlankMachineID(tc.id); got != tc.blank {
				t.Fatalf("isBlankMachineID(%q) = %v, want %v", tc.id, got, tc.blank)
			}
		})
	}
}
