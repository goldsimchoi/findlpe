package path

import "testing"

func TestParseMountInfoDecodesPathsAndClassifiesMounts(t *testing.T) {
	input := []byte("36 25 0:32 / / rw,nosuid - ext4 /dev/vda1 rw\n" +
		"40 36 0:40 /sub /srv/app\\040data ro,noexec,nosuid,relatime master:1 - ext4 /dev/vda2 ro\n" +
		"41 36 0:41 / /net rw,relatime - nfs server:/export rw\n" +
		"42 36 0:42 / /proc rw,nosuid,nodev,noexec - proc proc rw\n" +
		"43 36 0:32 /bind /mnt/bind rw,relatime - ext4 /dev/vda1 rw\n")
	mounts, diagnostics := ParseMountInfo(input, "e-mount")
	if len(diagnostics) != 0 || len(mounts) != 5 {
		t.Fatalf("ParseMountInfo = %#v, %#v", mounts, diagnostics)
	}
	nested, ok := MountForPath("/srv/app data/bin/tool", mounts)
	if !ok || nested.MountPoint != "/srv/app data" || !nested.ReadOnly || !nested.NoExec || !nested.NoSUID {
		t.Fatalf("nested mount = %#v, %v", nested, ok)
	}
	if mount, _ := MountForPath("/net/x", mounts); !mount.Remote {
		t.Fatalf("NFS mount not remote: %#v", mount)
	}
	if mount, _ := MountForPath("/proc/1", mounts); !mount.Pseudo {
		t.Fatalf("proc mount not pseudo: %#v", mount)
	}
	if mount, _ := MountForPath("/mnt/bind/x", mounts); !mount.Bind {
		t.Fatalf("bind mount not detected: %#v", mount)
	}
}

func TestMountSelectionHonorsPathBoundaries(t *testing.T) {
	mounts := []MountObservation{{MountPoint: "/", EvidenceIDs: []string{"e"}}, {MountPoint: "/srv/app", EvidenceIDs: []string{"e"}}}
	if mount, _ := MountForPath("/srv/application", mounts); mount.MountPoint != "/" {
		t.Fatalf("prefix without boundary selected nested mount: %#v", mount)
	}
}
