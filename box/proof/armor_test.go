package proof

import (
	"strings"
	"testing"
)

// One signature, one commit id: an SSH armor is read as ssh-keygen
// writes it and refused in every other spelling. ssh-keygen verifies
// each of those all the same, and each hashes to a commit the
// repository never had — a baseline no push could descend from
// (DESIGN-box.md, step 12).
func TestParseCommitReadsOneSpellingOfAnSSHArmor(t *testing.T) {
	commit := func(armor string) []byte {
		return commitObject(emptyTree, nil, []string{gpgsigHeader(armor)}, "msg\n")
	}
	if c, err := ParseCommit(commit(sshArmor)); err != nil || c.Kind != SSHSig {
		t.Fatalf("ssh-keygen's own armor, one line: %v", err)
	}
	// A blob long enough to wrap, armored as ssh-keygen armors it.
	long := string(ArmorSSH([]byte(strings.Repeat("SSHSIG\x00\x00\x00\x01", 24))))
	canonical, err := ParseCommit(commit(long))
	if err != nil || canonical.Kind != SSHSig || string(canonical.Signature) != long {
		t.Fatalf("ssh-keygen's own armor, wrapped: %v", err)
	}
	const begin, end = "-----BEGIN SSH SIGNATURE-----\n", "-----END SSH SIGNATURE-----\n"
	flat := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(long, begin), end), "\n", "")
	wrapped := func(n int) string {
		var lines []string
		for s := flat; s != ""; {
			k := min(n, len(s))
			lines = append(lines, s[:k])
			s = s[k:]
		}
		return begin + strings.Join(lines, "\n") + "\n" + end
	}
	for name, armor := range map[string]string{
		"wrapped at 64":             wrapped(64),
		"wrapped at 76":             wrapped(76),
		"one line":                  begin + flat + "\n" + end,
		"a blank line":              strings.Replace(long, "\n"+end, "\n\n"+end, 1),
		"a trailing space":          strings.Replace(long, "\n"+end, " \n"+end, 1),
		"a space in the body":       long[:len(begin)+10] + " " + long[len(begin)+10:],
		"CRLF":                      strings.ReplaceAll(long, "\n", "\r\n"),
		"the END line not last":     long + " \n",
		"nothing between the lines": begin + end,
	} {
		raw := commit(armor)
		if ObjectID("commit", raw) == canonical.ID {
			t.Fatalf("%s: the same commit id, so nothing to refuse", name)
		}
		_, err := ParseCommit(raw)
		if err == nil || !strings.Contains(err.Error(), "armored as ssh-keygen writes it") {
			t.Errorf("%s: %v, want the armor refused", name, err)
		}
	}
	// And one place for the header: the same armor moved up among the
	// headers is the same payload and signature under another id.
	moved := []byte("tree " + emptyTree + "\n" + gpgsigHeader(long) + "\nauthor Alice <alice@example.com> 1791000000 +0000\ncommitter Alice <alice@example.com> 1791000000 +0000\n\nmsg\n")
	if ObjectID("commit", moved) == canonical.ID {
		t.Fatal("the moved header hashes the same, so nothing to refuse")
	}
	if _, err := ParseCommit(moved); err == nil || !strings.Contains(err.Error(), "not the last header") {
		t.Errorf("a gpgsig header before the author: %v, want the place refused", err)
	}
}
