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

func vaultscanURLToPath(root, storageURL string) string {
	const prefix = "vaultscan://"
	if !strings.HasPrefix(storageURL, prefix) {
		return ""
	}
	parts := strings.SplitN(storageURL[len(prefix):], "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return filepath.Join(root, parts[0], parts[1]+".enc")
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
