package version

import "strings"

// appguard backend version, injected at build time
// go build -ldflags "-X github.com/servasec/appguard/backend/version.Version=<version>"
var Version = "develop"

func NormalizeVersion() string {
	return strings.TrimPrefix(Version, "v")
}
