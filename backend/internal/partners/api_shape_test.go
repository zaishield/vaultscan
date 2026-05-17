package partners

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// partners.Service is DB-bound; behaviour lives in integration tests.
// API shape lock here.

func TestNew_NilDepsPermitted(t *testing.T) {
	t.Parallel()
	if s := New(nil, nil, nil); s == nil {
		t.Fatal("New returned nil")
	}
}

func TestCreateInput_Fields(t *testing.T) {
	t.Parallel()
	parent := uuid.New()
	in := CreateInput{
		PlatformID: uuid.New(),
		ParentID:   &parent,
		TypeCode:   "reseller",
		Name:       "Acme Reseller",
		Slug:       "acme-resell",
	}
	v := reflect.ValueOf(in)
	for _, name := range []string{"PlatformID", "ParentID", "TypeCode", "Name", "Slug"} {
		if !v.FieldByName(name).IsValid() {
			t.Errorf("CreateInput missing %q", name)
		}
	}
}

func TestServiceMethods_Exist(t *testing.T) {
	t.Parallel()
	s := New(nil, nil, nil)
	_ = s.Create
	_ = s.Get
	_ = s.List
	_ = s.HierarchyForTenant
}

// Hierarchy struct is what HierarchyForTenant returns; it powers the
// portal's partner-tree view. A rename here is a portal-side break.
func TestHierarchy_Shape(t *testing.T) {
	t.Parallel()
	v := reflect.TypeOf(Hierarchy{})
	if v.NumField() == 0 {
		t.Fatal("Hierarchy has no fields")
	}
}
