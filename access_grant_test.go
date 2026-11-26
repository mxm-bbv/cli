package main

import (
	"strings"
	"testing"
	"time"
)

func TestGrantInputs(t *testing.T) {
	line, fp := newKey(t, "roma@laptop")
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	ok := map[string]string{"grant": "01a2-tunnel", "user": "s-101", "kind": "tunnel", "key": line, "expires": "202612031000", "port": "5432"}
	key, blob, port, until, err := grantInputs(ok, now)
	if err != nil || key.Fingerprint != fp || blob != strings.Fields(line)[1] || port != 5432 || !until.Equal(time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v %q %d %v %v", key, blob, port, until, err)
	}
	for field, bad := range map[string]string{
		"grant":   "Bad Grant",
		"user":    "root",
		"kind":    "files",
		"key":     `restrict ` + line,
		"expires": "202611260959",
		"port":    "70000",
	} {
		in := map[string]string{}
		for k, v := range ok {
			in[k] = v
		}
		in[field] = bad
		if _, _, _, _, err := grantInputs(in, now); err == nil || !strings.HasPrefix(err.Error(), field) {
			t.Errorf("%s=%q: %v", field, bad, err)
		}
	}
	for _, user := range []string{"deploy", "s-", "s-abc", "s-1;id"} {
		in := map[string]string{}
		for k, v := range ok {
			in[k] = v
		}
		in["user"] = user
		if _, _, _, _, err := grantInputs(in, now); err == nil {
			t.Errorf("user %q passed", user)
		}
	}
}

func TestGrantLine(t *testing.T) {
	line, fp := newKey(t, "roma@laptop")
	key, _ := parseAuthorizedKey(line)
	got := grantLine(key, strings.Fields(line)[1], "01a2-tunnel", time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC), 5432)
	want := `restrict,port-forwarding,permitopen="127.0.0.1:5432",expiry-time="` + time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC).In(time.Local).Format("200601021504") + `" `
	if !strings.HasPrefix(got, want) || !strings.HasSuffix(got, " studio-os:01a2-tunnel") || strings.Contains(got, "roma@laptop") {
		t.Fatalf("%q", got)
	}
	// The line is what sshd and access-list read: the same key, its options, the grant as its comment.
	parsed, ok := parseAuthorizedKey(got)
	if !ok || parsed.Fingerprint != fp || parsed.Comment != "studio-os:01a2-tunnel" || !strings.HasPrefix(parsed.Options, "restrict,") {
		t.Errorf("%+v", parsed)
	}
}

func TestWithGrant(t *testing.T) {
	a := `restrict,permitopen="127.0.0.1:5432" ssh-ed25519 AAAA studio-os:a`
	b := `restrict,permitopen="127.0.0.1:6379" ssh-ed25519 BBBB studio-os:b`
	a2 := `restrict,permitopen="127.0.0.1:5433" ssh-ed25519 AAAA studio-os:a`

	body, left := withGrant("", "a", a)
	if body != a+"\n" || left != 1 {
		t.Fatalf("add: %q %d", body, left)
	}
	body, left = withGrant(body+b+"\n", "a", a2)
	if body != b+"\n"+a2+"\n" || left != 2 {
		t.Fatalf("replace: %q %d", body, left)
	}
	body, left = withGrant(body, "a", "")
	if body != b+"\n" || left != 1 {
		t.Fatalf("remove: %q %d", body, left)
	}
	if body, left = withGrant(body, "b", ""); body != "" || left != 0 {
		t.Fatalf("last: %q %d", body, left)
	}
	if body, left = withGrant(b+"\n", "gone", ""); body != b+"\n" || left != 1 {
		t.Errorf("a grant not there: %q %d", body, left)
	}
}
