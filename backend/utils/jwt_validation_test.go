package utils

import "testing"

func TestValidateSecrets(t *testing.T) {
	valid := map[string]string{
		"JWT_SECRET":                       "jwt-secret-with-at-least-32-bytes-000",
		"REFRESH_SECRET":                   "refresh-secret-with-at-least-32-bytes",
		"CSRF_SECRET":                      "csrf-secret-with-at-least-32-bytes-00",
		"APPGUARD_FEATURES_ENCRYPTION_KEY": "encryption-key-with-at-least-32-bytes",
		"APPGUARD_ADMIN_PASSWORD":          "use-a-unique-password-here",
		"APPGUARD_PUBLIC_URL":              "https://appguard.example.com",
		"APPGUARD_PUBLIC_DOMAIN":           "appguard.example.com",
	}
	get := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	if err := validateSecrets(get(valid)); err != nil {
		t.Fatalf("valid secrets rejected: %v", err)
	}
	development := make(map[string]string, len(valid))
	for key, value := range valid {
		development[key] = value
	}
	development["APPGUARD_DEBUG_ENABLED"] = "true"
	development["APPGUARD_ADMIN_PASSWORD"] = ""
	development["APPGUARD_PUBLIC_URL"] = "http://appguard.local"
	development["APPGUARD_PUBLIC_DOMAIN"] = "appguard.local"
	if err := validateSecrets(get(development)); err != nil {
		t.Fatalf("development settings rejected: %v", err)
	}

	tests := []struct {
		name   string
		change func(map[string]string)
	}{
		{"missing jwt secret", func(values map[string]string) { values["JWT_SECRET"] = "" }},
		{"example csrf secret", func(values map[string]string) {
			values["CSRF_SECRET"] = "REPLACE_WITH_A_RANDOM_VALUE_THAT_IS_LONG_ENOUGH"
		}},
		{"short encryption key", func(values map[string]string) { values["APPGUARD_FEATURES_ENCRYPTION_KEY"] = "too-short" }},
		{"missing admin password", func(values map[string]string) { values["APPGUARD_ADMIN_PASSWORD"] = "" }},
		{"weak admin password", func(values map[string]string) { values["APPGUARD_ADMIN_PASSWORD"] = "short" }},
		{"example admin password", func(values map[string]string) { values["APPGUARD_ADMIN_PASSWORD"] = "Admin1234!" }},
		{"bcrypt limit", func(values map[string]string) { values["APPGUARD_ADMIN_PASSWORD"] = string(make([]byte, 73)) }},
		{"http public url", func(values map[string]string) { values["APPGUARD_PUBLIC_URL"] = "http://appguard.example.com" }},
		{"public host mismatch", func(values map[string]string) { values["APPGUARD_PUBLIC_DOMAIN"] = "other.example.com" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			tt.change(values)
			if err := validateSecrets(get(values)); err == nil {
				t.Fatal("expected secrets to be rejected")
			}
		})
	}
}
