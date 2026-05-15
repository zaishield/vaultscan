package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func signRef(key []byte, id string, exp int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "|" + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// parseObjectURL splits "vaultscan://<tenant>/<object>" into the two
// UUIDs. Returns (_, _, false) for any malformed input.
func parseObjectURL(storageURL string) (tenantID, objectID uuid.UUID, ok bool) {
	const prefix = "vaultscan://"
	if !strings.HasPrefix(storageURL, prefix) {
		return uuid.Nil, uuid.Nil, false
	}
	parts := strings.SplitN(storageURL[len(prefix):], "/", 2)
	if len(parts) != 2 {
		return uuid.Nil, uuid.Nil, false
	}
	tid, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	oid, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return tid, oid, true
}

// vaultscanURLToPath is the legacy filesystem helper retained for the
// FilesystemStorage backend's own internal use + the integration test
// that pokes at on-disk layout directly.
func vaultscanURLToPath(root, storageURL string) string {
	tenantID, objectID, ok := parseObjectURL(storageURL)
	if !ok {
		return ""
	}
	return filepath.Join(root, tenantID.String(), objectID.String()+".enc")
}

func ipOrNull(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
