// archive_fsops.go — real os.* wrappers for the package vars in
// archive.go. Split into its own file so test files can shadow these
// with in-memory stubs without dragging the os package into the test
// binary's exclusion list.
package audit

import "os"

func realMkdirAll(path string, perm uint32) error {
	return os.MkdirAll(path, os.FileMode(perm))
}

func realWriteFile(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}
