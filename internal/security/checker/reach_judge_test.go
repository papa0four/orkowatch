//go:build linux || freebsd

// internal/security/checker/reach_judge_test.go

package checker

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"testing"
)

// noID is the identifier of an entry that names no account or group.
const noID = ^uint32(0)

// judgeAnswering returns a judge that has already asked who holds root's
// group and was answered rootGroup, so a test reads no account database.
func judgeAnswering(rootGroup reachability) *deniedJudge {
	j := &deniedJudge{}
	j.once.Do(func() { j.rootGroup = rootGroup })
	return j
}

// The entries are the ones a FreeBSD 15.1 guest returned for directories of
// root:wheel on UFS mounted acls; a_w is uid 1001 and g_w gid 1002.
func TestACLReach(t *testing.T) {
	const (
		tagUserObj = 0x01
		tagOther   = 0x20
		read       = 0x04
		all        = 0x07
	)
	owner := aclEntry{tag: tagUserObj, perm: all, id: noID}
	other := aclEntry{tag: tagOther, id: noID}
	owningGroup := func(perm uint32) aclEntry { return aclEntry{tag: aclTagGroupObj, perm: perm, id: noID} }
	mask := func(perm uint32) aclEntry { return aclEntry{tag: aclTagMask, perm: perm, id: noID} }

	tests := []struct {
		name      string
		entries   []aclEntry
		rootGroup reachability
		want      reachability
	}{
		{"a user and a group named", []aclEntry{owner, {aclTagUser, aclPermExecute, 1001}, owningGroup(0), {aclTagGroup, aclPermExecute, 1002}, mask(aclPermExecute), other},
			reachRootOnly, reachNonRoot},
		{"a named user the mask caps", []aclEntry{owner, {aclTagUser, aclPermExecute, 1001}, owningGroup(0), mask(0), other},
			reachRootOnly, reachRootOnly},
		{"root named", []aclEntry{owner, {aclTagUser, aclPermExecute, rootUID}, owningGroup(0), mask(aclPermExecute), other},
			reachNonRoot, reachRootOnly},
		{"root's group named, held by root alone", []aclEntry{owner, owningGroup(0), {aclTagGroup, aclPermExecute, rootGID}, mask(aclPermExecute), other},
			reachRootOnly, reachRootOnly},
		{"root's group named, held by another", []aclEntry{owner, owningGroup(0), {aclTagGroup, aclPermExecute, rootGID}, mask(aclPermExecute), other},
			reachNonRoot, reachNonRoot},
		{"the owning group, no entry added", []aclEntry{owner, owningGroup(read | aclPermExecute), other},
			reachUndetermined, reachUndetermined},
		{"no entry grants a search", []aclEntry{owner, owningGroup(read), {aclTagGroup, read, 1002}, mask(all), other},
			reachNonRoot, reachRootOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := judgeAnswering(tt.rootGroup).aclReach(context.Background(), tt.entries); got != tt.want {
				t.Errorf("aclReach() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPosixReach(t *testing.T) {
	named := []aclEntry{{aclTagUser, aclPermExecute, 1001}, {aclTagMask, aclPermExecute, noID}}
	reads := func(entries []aclEntry, err error) func() ([]aclEntry, error) {
		return func() ([]aclEntry, error) { return entries, err }
	}

	failed := errors.New("input/output error")

	tests := []struct {
		name      string
		mode      fs.FileMode
		read      func() ([]aclEntry, error)
		rootGroup reachability
		want      reachability
	}{
		{"no group-execute, the list not read", fs.ModeDir | 0700, func() ([]aclEntry, error) {
			t.Error("the ACL was read for a directory with no group-execute")
			return named, nil
		}, reachNonRoot, reachRootOnly},
		{"group-execute and no list, root's group held by root alone", fs.ModeDir | 0750, reads(nil, errNoACL), reachRootOnly, reachRootOnly},
		{"group-execute and no list, root's group held by another", fs.ModeDir | 0750, reads(nil, errNoACL), reachNonRoot, reachNonRoot},
		{"group-execute and a list", fs.ModeDir | 0710, reads(named, nil), reachRootOnly, reachNonRoot},
		{"the list could not be read", fs.ModeDir | 0710, reads(nil, failed), reachRootOnly, reachUndetermined},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := judgeAnswering(tt.rootGroup).posixReach(context.Background(), tt.mode, tt.read); got != tt.want {
				t.Errorf("posixReach() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseNsswitch(t *testing.T) {
	const conf = `# /etc/nsswitch.conf
passwd:         files systemd
group:          files [NOTFOUND=return] sss # directory groups
shadow:         files
gshadow:        files [ SUCCESS = return ] ldap

hosts: files dns
netgroup
group_compat: nis
`
	want := []nsswitchLine{
		{"passwd", []string{"files", "systemd"}},
		{"group", []string{"files", "sss"}},
		{"shadow", []string{"files"}},
		{"gshadow", []string{"files", "ldap"}},
		{"hosts", []string{"files", "dns"}},
		{"group_compat", []string{"nis"}},
	}
	if got := parseNsswitch([]byte(conf)); !reflect.DeepEqual(got, want) {
		t.Errorf("parseNsswitch() = %v, want %v", got, want)
	}
}
