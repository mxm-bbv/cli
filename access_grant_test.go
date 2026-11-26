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
	admin := map[string]string{"grant": "01a2-admin", "user": "maks", "kind": "admin", "key": line, "expires": "202611270900"}
	if _, _, port, _, err := grantInputs(admin, now); err != nil || port != 0 {
		t.Fatalf("admin without a port: %d %v", port, err)
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
	for _, user := range []string{"Maks", "1max", "s 1", "max;id", ""} {
		in := map[string]string{}
		for k, v := range admin {
			in[k] = v
		}
		in["user"] = user
		if _, _, _, _, err := grantInputs(in, now); err == nil {
			t.Errorf("user %q passed", user)
		}
	}
	t.Setenv("SUDO_USER", "deploy")
	in := map[string]string{}
	for k, v := range admin {
		in[k] = v
	}
	in["user"] = "deploy"
	if _, _, _, _, err := grantInputs(in, now); err == nil {
		t.Error("the deploy user passed")
	}
}

func TestGrantLine(t *testing.T) {
	line, fp := newKey(t, "roma@laptop")
	key, _ := parseAuthorizedKey(line)
	until := time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)
	local := until.In(time.Local).Format("200601021504")

	tunnel := grantLine(kindTunnel, key, strings.Fields(line)[1], "01a2-tunnel", until, 5432)
	if !strings.HasPrefix(tunnel, `restrict,port-forwarding,permitopen="127.0.0.1:5432",expiry-time="`+local+`" `) || !strings.HasSuffix(tunnel, " studio-os:01a2-tunnel") || strings.Contains(tunnel, "roma@laptop") {
		t.Fatalf("%q", tunnel)
	}
	admin := grantLine(kindAdmin, key, strings.Fields(line)[1], "01a2-admin", until, 0)
	if admin != `expiry-time="`+local+`" `+strings.Join(strings.Fields(line)[:2], " ")+" studio-os:01a2-admin" {
		t.Fatalf("%q", admin)
	}
	// What sshd and access-list read: the same key, its options, the grant as its comment.
	for _, l := range []string{tunnel, admin} {
		if parsed, ok := parseAuthorizedKey(l); !ok || parsed.Fingerprint != fp || !strings.HasPrefix(parsed.Comment, "studio-os:") {
			t.Errorf("%+v", parsed)
		}
	}
}

func TestWithGrant(t *testing.T) {
	a := `restrict,permitopen="127.0.0.1:5432" ssh-ed25519 AAAA studio-os:a`
	b := `expiry-time="202612031000" ssh-ed25519 BBBB studio-os:b`
	own := `ssh-ed25519 CCCC maks@laptop`

	body, left, admins := withGrant(own+"\n", "a", a)
	if body != own+"\n"+a+"\n" || left != 1 || admins != 0 {
		t.Fatalf("add: %q %d %d", body, left, admins)
	}
	body, left, admins = withGrant(body, "b", b)
	if left != 2 || admins != 1 {
		t.Fatalf("admin: %q %d %d", body, left, admins)
	}
	body, left, admins = withGrant(body, "b", "")
	if body != own+"\n"+a+"\n" || left != 1 || admins != 0 {
		t.Fatalf("remove admin: %q %d %d", body, left, admins)
	}
	if body, left, _ = withGrant(body, "a", ""); body != own+"\n" || left != 0 {
		t.Fatalf("last grant, own key stays: %q %d", body, left)
	}
	if body, left, _ = withGrant(b+"\n", "gone", ""); body != b+"\n" || left != 1 {
		t.Errorf("a grant not there: %q %d", body, left)
	}
}
