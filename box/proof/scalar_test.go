package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshsigCommit is a signed commit object whose SSHSIG envelope holds
// the given key, reserved field and inner signature, armored as
// ssh-keygen writes it. ParseCommit verifies nothing, so what was
// signed does not matter here.
func sshsigCommit(pub []byte, reserved string, s *ssh.Signature) []byte {
	blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Version                   uint32
		PublicKey                 []byte
		Namespace, Reserved, Hash string
		Signature                 []byte
	}{1, pub, "git", reserved, "sha512", ssh.Marshal(s)})...)
	return commitObject(emptyTree, nil, []string{gpgsigHeader(string(ArmorSSH(blob)))}, "msg\n")
}

// One signature, one commit id, for the blob as for the armor: each of
// these verifies under ssh-keygen as the signer's own does (OpenSSH
// 10.0, measured 2026-11-06 and -07 through Verifier: `Good "git"
// signature` for each), and hashes to a commit the repository never
// had. No signer writes one, so each is refused as a bundle error
// (DESIGN-box.md, step 12). An ECDSA signature's (r, n−s) has no such
// rule, so ECDSA is no longer a signer type (TestParseSigner).
func TestParseCommitReadsOneSpellingOfAnSSHSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(rand.Reader, []byte("anything"))
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey().Marshal()
	canonical, err := ParseCommit(sshsigCommit(pub, "", sig))
	if err != nil || canonical.Kind != SSHSig {
		t.Fatalf("the signer's own signature: %v", err)
	}
	refused := func(name string, raw []byte, want string) {
		t.Helper()
		if ObjectID("commit", raw) == canonical.ID {
			t.Fatalf("%s: the twin hashes the same, so nothing to refuse", name)
		}
		if _, err := ParseCommit(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
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
	refused("S + L", sshsigCommit(pub, "", twin), "not below the group order")

	// The reserved field, which the signature does not cover and
	// ssh-keygen reads as empty whatever it holds.
	refused("reserved field set", sshsigCommit(pub, "x", sig), "reserved field is not empty")

	// An RSA signature a byte short, which ssh-keygen pads back: the
	// honest spelling of one signature in 256, whose top byte is zero.
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	rsig, err := rs.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, []byte("anything"), ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	rpub := rs.PublicKey().Marshal()
	if c, err := ParseCommit(sshsigCommit(rpub, "", rsig)); err != nil || c.Kind != SSHSig {
		t.Fatalf("the RSA signer's own signature: %v", err)
	}
	short := &ssh.Signature{Format: rsig.Format, Blob: rsig.Blob[1:]}
	refused("RSA signature a byte short", sshsigCommit(rpub, "", short), "length of the key's modulus")
	long := &ssh.Signature{Format: rsig.Format, Blob: append([]byte{0}, rsig.Blob...)}
	refused("RSA signature a byte long", sshsigCommit(rpub, "", long), "length of the key's modulus")

	// A blob of another shape is ssh-keygen's to judge, as before: the
	// armor test's dummy blob still parses.
	if c, err := ParseCommit(commitObject(emptyTree, nil, []string{gpgsigHeader(sshArmor)}, "msg\n")); err != nil || c.Kind != SSHSig {
		t.Fatalf("a blob that is no SSHSIG: %v", err)
	}
}
