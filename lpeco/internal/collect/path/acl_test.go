package path

import (
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestParseACLAndEffectivePermissionMatrix(t *testing.T) {
	acls, diagnostics := ParseACL([]byte("LPECO_PATH_ACL_V1\nACL\t2f7372762f617070\nuser::rw-\nuser:1000:rwx\ngroup::r--\ngroup:2000:rwx\nmask::r-x\nother::---\ndefault:user:1000:rwx\nEND_ACL\n"), "e-acl")
	if len(diagnostics) != 0 || len(acls) != 1 {
		t.Fatalf("ParseACL = %#v, %#v", acls, diagnostics)
	}
	acl := acls[0]
	if len(acl.Entries) != 7 || acl.Entries[6].Default != true {
		t.Fatalf("ACL entries = %#v", acl.Entries)
	}
	file := statFile("/srv/app", 1, 42, 43, 0o640)
	tests := []struct {
		name      string
		principal model.Principal
		want      PermissionSet
	}{
		{name: "owner uses owner entry without mask", principal: model.Principal{UID: 42, GID: 1}, want: PermissionSet{Read: true, Write: true}},
		{name: "named user is limited by mask", principal: model.Principal{UID: 1000, GID: 1}, want: PermissionSet{Read: true, Execute: true}},
		{name: "supplementary named group is limited by mask", principal: model.Principal{UID: 1001, GID: 1, SupplementaryGIDs: []int{2000}}, want: PermissionSet{Read: true, Execute: true}},
		{name: "owning group", principal: model.Principal{UID: 1001, GID: 43}, want: PermissionSet{Read: true}},
		{name: "other", principal: model.Principal{UID: 1001, GID: 1}, want: PermissionSet{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := EffectivePermissions(tt.principal, file, acl)
			if !known || got != tt.want {
				t.Fatalf("EffectivePermissions = %#v, %v; want %#v, true", got, known, tt.want)
			}
		})
	}
}

func TestDefaultACLDoesNotGrantCurrentAccessAndUnavailableIsUnknown(t *testing.T) {
	file := statFile("/srv/app", 1, 42, 43, 0o600)
	defaultOnly := ACLObservation{Path: file.Path, Status: ObservationComplete, Entries: []ACLEntry{{Tag: ACLNamedUser, Qualifier: 1000, Permissions: PermissionSet{Write: true}, Default: true}}}
	permissions, known := EffectivePermissions(model.Principal{UID: 1000, GID: 1000}, file, defaultOnly)
	if !known || permissions.Write {
		t.Fatalf("default ACL affected access: %#v, known=%v", permissions, known)
	}
	if _, known := EffectivePermissions(model.Principal{UID: 1000}, file, ACLObservation{Path: file.Path, Status: ObservationUnavailable}); known {
		t.Fatal("unavailable ACL was treated as known")
	}
}

func TestNamedACLWithoutMaskIsUnknown(t *testing.T) {
	file := statFile("/srv/app", 1, 42, 43, 0o600)
	acl := ACLObservation{Path: file.Path, Status: ObservationComplete, Entries: []ACLEntry{
		{Tag: ACLUser, Qualifier: -1, Permissions: PermissionSet{Read: true, Write: true}},
		{Tag: ACLNamedUser, Qualifier: 1000, Permissions: PermissionSet{Write: true}},
		{Tag: ACLOther, Qualifier: -1},
	}}
	if _, known := EffectivePermissions(model.Principal{UID: 1000}, file, acl); known {
		t.Fatal("named ACL without a mask was treated as complete")
	}
}
