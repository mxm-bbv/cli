package update

import (
	"testing"

	"github.com/mxm-bbv/cli/internal/steps"
)

// A real minisign signature over the bytes "hello forge\n", produced with
// forge's release key (prehashed "ED" format). This locks in that our
// in-process verifier accepts a genuine signature and rejects tampering.
const sampleSig = `untrusted comment: signature from minisign secret key
RUSk3LOux6EkxQ57yfCpuqVvIdMT81ot0QLnYBPQwCeqAll/A7cgLZlFaAKPfWyeplo4za0o2FQ4grz6NrfrLmxGUSEV5Rr7PgE=
trusted comment: timestamp:1784075450	file:sample.txt	hashed
a7IFYtWpc2anmqz/L2KyA2ReKob4xky0cE0R31tSW/JpTJcJmqg+TRtsJCbF3NU+tTkTOY7FQqkpP1BgtT2kBg==
`

func TestVerifyMinisignValid(t *testing.T) {
	if err := verifyMinisign(steps.ReleasePubKey, []byte(sampleSig), []byte("hello forge\n")); err != nil {
		t.Fatalf("expected a valid signature to verify, got: %v", err)
	}
}

func TestVerifyMinisignRejectsTamperedContent(t *testing.T) {
	if err := verifyMinisign(steps.ReleasePubKey, []byte(sampleSig), []byte("hello forge!\n")); err == nil {
		t.Fatal("expected verification to FAIL on modified content")
	}
}

func TestVerifyMinisignRejectsWrongKey(t *testing.T) {
	// Flip the algorithm-ok but wrong key: a different valid minisign pubkey.
	const otherKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QzKMXPRdT5jZK"
	if err := verifyMinisign(otherKey, []byte(sampleSig), []byte("hello forge\n")); err == nil {
		t.Fatal("expected verification to FAIL against a non-matching key")
	}
}
