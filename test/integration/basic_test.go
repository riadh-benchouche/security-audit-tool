package integration

import (
	"os/exec"
	"testing"
)

func TestBasicCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"version", []string{"version"}},
		{"modules", []string{"modules"}},
		{"health", []string{"modules", "health"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command("../../build/security-audit", test.args...)
			err := cmd.Run()
			if err != nil {
				t.Errorf("Command failed: %v", err)
			}
		})
	}
}
