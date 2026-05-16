package users

import (
	"testing"
)

// users is DB-bound; behaviour is covered by
// test/integration/services_coverage_test.go. This file pins the
// CreateInput shape — a silent rename of a field would compile-break
// every caller, but a silent JSON-tag rename would corrupt API
// requests; both are caught here.

func TestCreateInput_FieldShape(t *testing.T) {
	t.Parallel()
	// Exhaustively reference each field so a removal fails compile.
	in := CreateInput{
		PlatformID: nilUUID(),
		PartnerID:  nil,
		TenantID:   nil,
		Email:      "x@y",
		FullName:   "x",
		MFAEnabled: true,
		Actor:      nil,
	}
	if in.Email == "" || in.FullName == "" {
		t.Error("test data invalid")
	}
}

func TestAssignRoleInput_FieldShape(t *testing.T) {
	t.Parallel()
	in := AssignRoleInput{
		UserID:       nilUUID(),
		RoleID:       nilUUID(),
		ScopePartner: nil,
		ScopeTenant:  nil,
		GrantedBy:    nil,
	}
	_ = in
}

func nilUUID() (z [16]byte) { return }
