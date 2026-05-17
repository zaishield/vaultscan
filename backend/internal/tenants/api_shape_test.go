package tenants

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// tenants.Service is a thin pgx wrapper; behaviour is exercised in
// the integration suite. These tests pin the public API surface so a
// rename surfaces here rather than in every API handler.

func TestNew_NilDepsPermitted(t *testing.T) {
	t.Parallel()
	if s := New(nil, nil, nil); s == nil {
		t.Fatal("New(nil, nil, nil) returned nil")
	}
}

func TestCreateInput_Fields(t *testing.T) {
	t.Parallel()
	in := CreateInput{
		PlatformID:    uuid.New(),
		PartnerID:     uuid.New(),
		Name:          "Acme",
		Slug:          "acme",
		IsolationMode: "shared",
	}
	v := reflect.ValueOf(in)
	for _, name := range []string{"PlatformID", "PartnerID", "Name", "Slug", "IsolationMode"} {
		if !v.FieldByName(name).IsValid() {
			t.Errorf("CreateInput missing %q", name)
		}
	}
}

func TestListFilter_Fields(t *testing.T) {
	t.Parallel()
	f := ListFilter{}
	v := reflect.ValueOf(f)
	// At least one filter field must exist — without it the List()
	// query signature would have to change.
	if v.NumField() == 0 {
		t.Fatal("ListFilter has no fields")
	}
}

func TestServiceMethods_Exist(t *testing.T) {
	t.Parallel()
	// Catch a refactor that removes any of the public Service
	// methods Mount/server.go expects to dispatch on.
	s := New(nil, nil, nil)
	_ = s.Create
	_ = s.Get
	_ = s.List
	_ = s.Suspend
	_ = s.Reactivate
}
