package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// versionLen is the number of hex characters used for the short version id.
const versionLen = 12

// computeHash returns a stable SHA-256 hex digest of the merged config. The
// digest is content-addressed: identical config (regardless of file ordering,
// which Merge already normalizes) yields the same hash, so an unchanged reload
// is a no-op swap and the active version is meaningful.
func computeHash(cfg *config.MergedConfig) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("hash config: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// shortVersion derives a human-friendly version id from a full hash.
func shortVersion(hash string) string {
	if len(hash) <= versionLen {
		return hash
	}
	return hash[:versionLen]
}
