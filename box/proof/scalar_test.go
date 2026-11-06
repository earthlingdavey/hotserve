package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// One signature, one commit id, for the scalar as for the armor: an
// Ed25519 signature with S + L in place of S verifies under ssh-keygen
// all the same (OpenSSH 10.0, measured 2026-11-06: `Good "git"
// signature` for both), and hashes to a commit the repository never
// had. No signer writes one, so it is refused as a bundle error
// (DESIGN-box.md, step 12). An ECDSA signature's (r, n−s) has no such
// rule, so ECDSA is no longer a signer type (TestParseSigner).
func TestParseCommitReadsOneScalarOfAnEd25519Signature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// ParseCommit verifies nothing, so what was signed does not matter.
	sig, err := signer.Sign(rand.Reader, []byte("anything"))
	if err != nil {
		t.Fatal(err)
	}
	commit := func(s *ssh.Signature) []byte {
		blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
			Version                   uint32
			PublicKey                 []byte
			Namespace, Reserved, Hash string
			Signature                 []byte
		}{1, signer.PublicKey().Marshal(), "git", "", "sha512", ssh.Marshal(s)})...)
		return commitObject(emptyTree, nil, []string{gpgsigHeader(string(ArmorSSH(blob)))}, "msg\n")
	}
	canonical, err := ParseCommit(commit(sig))
	if err != nil || canonical.Kind != SSHSig {
		t.Fatalf("the signer's own signature: %v", err)
	}
	// S + L, in the signature's little-endian 32 bytes.
	S := new(big.Int)
	for i := 63; i >= 32; i-- {
		S.Lsh(S, 8)
		S.Or(S, big.NewInt(int64(sig.Blob[i])))
	}
	if S.Cmp(ed25519Order) >= 0 {
		t.Fatal("the signer wrote S at or above L")
	}
	S.Add(S, ed25519Order)
	twin := &ssh.Signature{Format: sig.Format, Blob: append([]byte{}, sig.Blob[:32]...)}
	buf := make([]byte, 32)
	S.FillBytes(buf)
	for i := 31; i >= 0; i-- {
		twin.Blob = append(twin.Blob, buf[i])
	}
	raw := commit(twin)
	if ObjectID("commit", raw) == canonical.ID {
		t.Fatal("the twin hashes the same, so nothing to refuse")
	}
	if _, err := ParseCommit(raw); err == nil || !strings.Contains(err.Error(), "not below the group order") {
		t.Errorf("S + L: %v, want the scalar refused", err)
	}
	// A blob of another shape is ssh-keygen's to judge, as before: the
	// armor test's dummy blob still parses.
	if c, err := ParseCommit(commitObject(emptyTree, nil, []string{gpgsigHeader(sshArmor)}, "msg\n")); err != nil || c.Kind != SSHSig {
		t.Fatalf("a blob that is no SSHSIG: %v", err)
	}
}
