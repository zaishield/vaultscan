// storage_filesystem.go — local-disk Storage backend (dev / single-node).
//
// Layout: <rootDir>/<tenant_uuid>/<object_uuid>.enc with mode 0600 and
// the parent directory created with mode 0700.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type FilesystemStorage struct {
	rootDir string
}

func NewFilesystemStorage(rootDir string) (*FilesystemStorage, error) {
	if rootDir == "" {
		return nil, errors.New("evidence: filesystem rootDir required")
	}
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("evidence: mkdir %s: %w", rootDir, err)
	}
	return &FilesystemStorage{rootDir: rootDir}, nil
}

func (f *FilesystemStorage) Name() string { return "filesystem" }

func (f *FilesystemStorage) Put(_ context.Context, tenantID, objectID uuid.UUID, blob []byte) error {
	dir := filepath.Join(f.rootDir, tenantID.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, objectID.String()+".enc"), blob, 0o600)
}

func (f *FilesystemStorage) Get(_ context.Context, tenantID, objectID uuid.UUID) ([]byte, error) {
	path := filepath.Join(f.rootDir, tenantID.String(), objectID.String()+".enc")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, path)
		}
		return nil, err
	}
	return data, nil
}

func (f *FilesystemStorage) Delete(_ context.Context, tenantID, objectID uuid.UUID) error {
	path := filepath.Join(f.rootDir, tenantID.String(), objectID.String()+".enc")
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
