package controllers

import "testing"

func TestValidateManagedPermission(t *testing.T) {
	tests := []struct {
		name          string
		subject       string
		resource      string
		action        string
		allowWildcard bool
		wantValid     bool
	}{
		{"scoped read", "user:12", "/applications/4", "read", false, true},
		{"scoped team write", "team:7", "/groups/3", "write", false, true},
		{"wildcard revocation", "team:7", "/groups/3", "*", true, true},
		{"reject wildcard grant", "user:12", "/applications/4", "*", false, false},
		{"reject role subject", "admin", "/applications/4", "read", false, false},
		{"reject arbitrary path", "user:12", "/*", "*", true, false},
		{"reject nested path", "user:12", "/applications/4/findings", "read", false, false},
		{"reject zero id", "user:0", "/applications/4", "read", false, false},
		{"reject unknown action", "user:12", "/applications/4", "delete", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := validateManagedPermission(tt.subject, tt.resource, tt.action, tt.allowWildcard)
			if gotValid := err == nil; gotValid != tt.wantValid {
				t.Fatalf("valid = %v, want %v (error: %v)", gotValid, tt.wantValid, err)
			}
		})
	}
}
