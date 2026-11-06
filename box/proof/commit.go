package proof

import (
	"bytes"
	"encoding/base64"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// MaxCommit bounds a commit object (DESIGN-box.md, "Store rules").
const MaxCommit = 64 << 10

// SigKind is what a commit's gpgsig header holds.
type SigKind int

const (
	// Unsigned is a commit with no gpgsig header.
	Unsigned SigKind = iota
	// SSHSig is an OpenSSH signature (`-----BEGIN SSH SIGNATURE-----`),
	// the only kind the box verifies.
	SSHSig
	// OpenPGPSig is a GnuPG signature — what GitHub's merge button
	// produces — refused by name.
	OpenPGPSig
	// OtherSig is a gpgsig header of neither form (X.509, say).
	OtherSig
)

// Commit is a parsed commit object. ID is computed from Raw; Payload is
// Raw with the gpgsig header removed, continuation lines included —
// git's rule for what a signature covers — and Signature is that
// header's value unfolded, the bytes ssh-keygen reads.
type Commit struct {
	Raw       []byte
	ID        string
	Tree      string
	Parents   []string
	Kind      SigKind
	Signature []byte
	Payload   []byte
}

// ParseCommit reads a commit object under strict rules: at most
// MaxCommit bytes; the first header is `tree` with a 40-hex id; every
// `parent` is a 40-hex id; a header's continuation lines begin with a
// space; at most one `gpgsig`; no `gpgsig-sha256` and no 64-hex id,
// which are a SHA-256 repository. Headers it does not know (author,
// committer, encoding, mergetag, …) are kept as bytes of the payload,
// which is where they belong. What it refuses, it refuses as a bundle
// error, except the SHA-256 case, which is named for the operator.
func ParseCommit(raw []byte) (*Commit, error) {
	if len(raw) > MaxCommit {
		return nil, refuse("bundle: commit object is larger than 64 KiB")
	}
	c := &Commit{Raw: raw, ID: ObjectID("commit", raw)}
	sep := bytes.Index(raw, []byte("\n\n"))
	if sep < 0 {
		return nil, refuse("bundle: commit: no blank line between the headers and the message")
	}
	header := raw[:sep+1] // every header line, each ending in "\n"
	payload := make([]byte, 0, len(raw))
	var sig []byte
	inSig, sigs, afterSig := false, 0, false
	for i, line := range bytes.SplitAfter(header, []byte("\n")) {
		if len(line) == 0 { // SplitAfter's trailing empty piece
			continue
		}
		if line[0] == ' ' { // a continuation line of the header above
			if i == 0 {
				return nil, refuse("bundle: commit: the first header is not tree")
			}
			if inSig {
				sig = append(sig, line[1:]...)
			} else {
				payload = append(payload, line...)
			}
			continue
		}
		if inSig {
			afterSig = true // a header after the signature's
		}
		inSig = false
		key, value, ok := bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if !ok || len(key) == 0 || !printableASCII(key) {
			return nil, refuse("bundle: commit: a header line is not `name value`")
		}
		if i == 0 && string(key) != "tree" {
			return nil, refuse("bundle: commit: the first header is not tree")
		}
		switch string(key) {
		case "tree":
			if i != 0 {
				return nil, refuse("bundle: commit: a second tree header")
			}
			switch formOfID(string(value)) {
			case idSHA1:
				c.Tree = string(value)
			case idSHA256:
				return nil, sha256RepoRefusal(c.ID)
			default:
				return nil, refuse("bundle: commit: the tree id is not 40 hex characters")
			}
		case "parent":
			switch formOfID(string(value)) {
			case idSHA1:
				c.Parents = append(c.Parents, string(value))
			case idSHA256:
				return nil, sha256RepoRefusal(c.ID)
			default:
				return nil, refuse("bundle: commit: a parent id is not 40 hex characters")
			}
		case "gpgsig":
			sigs++
			if sigs > 1 {
				return nil, refuse("bundle: commit: more than one gpgsig header")
			}
			inSig = true
			sig = append(append(sig, value...), '\n')
			continue // not part of the payload
		case "gpgsig-sha256":
			return nil, sha256RepoRefusal(c.ID)
		}
		payload = append(payload, line...)
	}
	if c.Tree == "" {
		return nil, refuse("bundle: commit: the first header is not tree")
	}
	payload = append(payload, raw[sep+1:]...) // the blank line and the message, verbatim
	c.Payload = payload
	if sigs == 1 {
		// git signs the headers it has and appends gpgsig as the last
		// (commit.c, sign_with_header); the payload is the same wherever
		// the header sits, the id is not, so one position is read — the
		// armor's rule (canonicalSSHArmor), for the header's place.
		if afterSig {
			return nil, refuse("bundle: commit: the gpgsig header is not the last header, where git writes it: the box reads one place for a signature, since the commit's id covers the header's place and the signature does not")
		}
		c.Signature = sig
		switch {
		case bytes.HasPrefix(sig, []byte("-----BEGIN SSH SIGNATURE-----")):
			blob, ok := canonicalSSHArmor(sig)
			if !ok {
				return nil, refuse("bundle: commit: the SSH signature is not armored as ssh-keygen writes it (its base64 in lines of 70 characters between the BEGIN and END lines, and nothing else): the box reads one spelling of a signature, since the commit's id covers the armor and the signature does not — sign with ssh-keygen, git's own gpg.ssh.program")
			}
			if !canonicalScalar(blob) {
				return nil, refuse("bundle: commit: the Ed25519 signature's S is not below the group order, where every signer writes it: the box reads one spelling of a signature, since the commit's id covers its bytes and ssh-keygen verifies S and S + L alike")
			}
			c.Kind = SSHSig
		case bytes.HasPrefix(sig, []byte("-----BEGIN PGP SIGNATURE-----")):
			c.Kind = OpenPGPSig
		default:
			c.Kind = OtherSig
		}
	}
	return c, nil
}

// printableASCII is true for a header name as git writes one: no
// space, no control byte, nothing outside ASCII.
func printableASCII(b []byte) bool {
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// canonicalSSHArmor says whether sig is an SSH signature's armor as
// ssh-keygen writes it and git stores it: the BEGIN line, the blob's
// base64 in lines of 70 characters (the last one shorter), the END
// line, each ending in "\n", and nothing else. The commit's id hashes
// the armor; the signature covers the commit without it. So every other
// spelling of one signature — the base64 re-wrapped, a blank or a
// space-padded line, which ssh-keygen reads all the same — would be a
// second commit id for the one signed payload, and a baseline the
// repository never had (DESIGN-box.md, step 12). The blob under the
// armor comes back with the verdict, for canonicalScalar.
func canonicalSSHArmor(sig []byte) ([]byte, bool) {
	const begin, end = "-----BEGIN SSH SIGNATURE-----\n", "-----END SSH SIGNATURE-----\n"
	if len(sig) < len(begin)+len(end) || !bytes.HasPrefix(sig, []byte(begin)) || !bytes.HasSuffix(sig, []byte(end)) {
		return nil, false
	}
	body := sig[len(begin) : len(sig)-len(end)]
	blob, err := base64.StdEncoding.DecodeString(string(bytes.ReplaceAll(body, []byte("\n"), nil)))
	if err != nil || len(blob) == 0 {
		return nil, false
	}
	return blob, bytes.Equal(sig, ArmorSSH(blob))
}

// ed25519Order is L, the order of Ed25519's base point (RFC 8032):
// 2^252 + 27742317777372353535851937790883648493.
var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// canonicalScalar says whether an Ed25519 signature in the SSHSIG blob
// has its S below the group order — the one value a signer writes, and
// what RFC 8032 has a verifier reject otherwise. ssh-keygen does not:
// it verifies S + L as the same signature (OpenSSH 10.0, measured), and
// the commit's id covers the bytes, so S + L would be a second commit
// id for one signed payload, as a re-wrapped armor would. The armor's
// rule, for the scalar. A signature of another key type, or a blob this
// cannot read, is ssh-keygen's to judge: an ECDSA signature's (r, n−s)
// is a signer's own form as much as (r, s), with no spelling to hold it
// to, and stays owed (DESIGN-box.md, Triage).
func canonicalScalar(blob []byte) bool {
	var sig struct {
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}
	if err := ssh.Unmarshal(bytes.TrimPrefix(blob, []byte("SSHSIG")), &sig); err != nil {
		return true
	}
	var inner struct {
		Format string
		Blob   []byte
		Rest   []byte `ssh:"rest"` // an sk- signature's flags and counter
	}
	if err := ssh.Unmarshal(sig.Signature, &inner); err != nil || len(inner.Blob) != 64 {
		return true
	}
	switch inner.Format {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
	default:
		return true
	}
	// S is the second half, little-endian.
	s := make([]byte, 32)
	for i, b := range inner.Blob[32:] {
		s[31-i] = b
	}
	return new(big.Int).SetBytes(s).Cmp(ed25519Order) < 0
}

// ArmorSSH is the one armor of blob the box reads (canonicalSSHArmor):
// what ssh-keygen writes. The test harness signs with it too, so the
// fixtures and the rule cannot drift apart.
func ArmorSSH(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70])
		out.WriteByte('\n')
		b64 = b64[70:]
	}
	out.WriteString(b64)
	out.WriteString("\n-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}
