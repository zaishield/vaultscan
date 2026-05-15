// factory.go — config-driven Storage construction. Used by all four
// cmd/* binaries (api, agent-gateway, scanner-worker, cron-runner) so
// the storage choice is consistent across the fleet.
package evidence

import (
	"fmt"
	"os"
	"path/filepath"
)

// StorageConfig is what every cmd builds from internal/config.Config
// before calling NewStorageFromConfig.
type StorageConfig struct {
	Backend          string  // "filesystem" | "s3"
	FilesystemRoot   string  // when Backend=filesystem
	S3Endpoint       string
	S3Bucket         string
	S3Region         string
	S3AccessKey      string
	S3SecretKey      string
	S3SessionToken   string
	S3ForcePathStyle bool
	S3SSE            string
}

// NewStorageFromConfig returns a Storage backend selected by cfg.Backend.
// "filesystem" is the safe default for dev / single-node.
func NewStorageFromConfig(cfg StorageConfig) (Storage, error) {
	switch cfg.Backend {
	case "", "filesystem":
		root := cfg.FilesystemRoot
		if root == "" {
			root = filepath.Join(os.TempDir(), "vaultscan-evidence")
		}
		return NewFilesystemStorage(root)
	case "s3", "minio", "ceph", "r2":
		return NewS3Storage(S3Config{
			Endpoint:        cfg.S3Endpoint,
			Bucket:          cfg.S3Bucket,
			Region:          cfg.S3Region,
			AccessKeyID:     cfg.S3AccessKey,
			SecretAccessKey: cfg.S3SecretKey,
			SessionToken:    cfg.S3SessionToken,
			ForcePathStyle:  cfg.S3ForcePathStyle,
			SSEHeader:       cfg.S3SSE,
		})
	default:
		return nil, fmt.Errorf("evidence: unknown backend %q (want: filesystem | s3)", cfg.Backend)
	}
}
