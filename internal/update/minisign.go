package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// verifyMinisign checks a minisign signature (sigFile contents) over content,
// using the given base64 minisign public key. It supports the modern prehashed
// ("ED", BLAKE2b-512) format that current minisign produces, and the legacy
// ("Ed") format. It returns nil only on a valid signature from the matching key.
//
// Implemented in-process (no external minisign binary on the server) so
// `forge update` can fail closed on any tampering.
func verifyMinisign(pubKeyB64 string, sigFile []byte, content []byte) error {
	pub, keyID, err := parseMinisignPubKey(pubKeyB64)
	if err != nil {
		return err
	}

	// The signature file's second non-comment line holds the base64 signature.
	var sigB64 string
	for _, line := range strings.Split(string(sigFile), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted comment:") || strings.HasPrefix(line, "trusted comment:") {
			continue
		}
		sigB64 = line
		break
	}
	if sigB64 == "" {
		return errors.New("minisign: no signature line found")
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("minisign: decode signature: %w", err)
	}
	if len(raw) != 2+8+64 {
		return fmt.Errorf("minisign: unexpected signature length %d", len(raw))
	}
	algo := string(raw[0:2])
	sigKeyID := raw[2:10]
	sig := raw[10:74]

	if !bytes.Equal(sigKeyID, keyID) {
		return errors.New("minisign: signature key ID does not match the pinned public key")
	}

	var msg []byte
	switch algo {
	case "ED": // prehashed: sign BLAKE2b-512 of the content
		h := blake2b.Sum512(content)
		msg = h[:]
	case "Ed": // legacy: sign the content directly
		msg = content
	default:
		return fmt.Errorf("minisign: unsupported algorithm %q", algo)
	}

	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("minisign: signature verification FAILED — refusing to trust the download")
	}
	return nil
}

// parseMinisignPubKey decodes a base64 minisign public key into its ed25519 key
// and 8-byte key ID.
func parseMinisignPubKey(b64 string) (ed25519.PublicKey, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, nil, fmt.Errorf("minisign: decode public key: %w", err)
	}
	if len(raw) != 2+8+32 {
		return nil, nil, fmt.Errorf("minisign: unexpected public key length %d", len(raw))
	}
	if string(raw[0:2]) != "Ed" {
		return nil, nil, fmt.Errorf("minisign: unsupported public key algorithm %q", string(raw[0:2]))
	}
	return ed25519.PublicKey(raw[10:42]), raw[2:10], nil
}
