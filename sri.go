// Package sri implements a Subresource Integrity checker for Go.
// See https://www.w3.org/TR/SRI/ for more information.
package sri

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// A Checker implements checking of a resource against a given subresource integrity string.
//
// It is not safe for concurrent use; each Checker corresponds to a single resource to be checked.
//
// After creation you would typically use it as a Writer to add data to it, then call Check to
// verify that the content matches the original expression.
type Checker struct {
	expected map[string][]string
	hashes   map[string]hash.Hash
	w        io.Writer
}

// A HashFunc is simply a function that returns a new Hash instance.
type HashFunc func() hash.Hash

// NewChecker creates a new Checker from the given string.
// It supports SHA256, SHA384 and SHA512 (although will only calculate those needed for the input).
// Use NewCheckerForHashes if you need support for additional hash types.
func NewChecker(sri string) (*Checker, error) {
	return NewCheckerForHashes(sri, map[string]HashFunc{
		"sha256": sha256.New,
		"sha384": sha512.New384,
		"sha512": sha512.New,
	})
}

// NewCheckerWithSHA1 is like NewChecker but adds SHA1 as an optional hash type.
// This is generally useful only for compatibility and is *not* recommended by the standard, so use
// at your own risk.
func NewCheckerWithSHA1(sri string) (*Checker, error) {
	return NewCheckerForHashes(sri, map[string]HashFunc{
		"sha1":   sha1.New,
		"sha256": sha256.New,
		"sha384": sha512.New384,
		"sha512": sha512.New,
	})
}

// NewCheckerForHashes creates a new Checker from the given string and set of hashes.
// It does not add any hashes by default, although will still only calculate those required by the SRI string given.
func NewCheckerForHashes(sri string, hashes map[string]HashFunc) (*Checker, error) {
	c := &Checker{
		expected: map[string][]string{},
		hashes:   map[string]hash.Hash{},
	}
	writers := []io.Writer{}
	for _, field := range strings.Fields(sri) {
		idx := strings.IndexRune(field, '-')
		if idx == -1 {
			return nil, fmt.Errorf("Invalid subresource integrity substring: %s", field)
		}
		if h, err := c.addHash(field[:idx], field[idx+1:], hashes); err != nil {
			return nil, err
		} else if h != nil {
			writers = append(writers, h)
		}
	}
	if len(writers) == 0 {
		return nil, fmt.Errorf("Invalid subresource integrity string (empty?): %s", sri)
	} else if len(writers) == 1 {
		c.w = writers[0]
	} else {
		c.w = io.MultiWriter(writers...)
	}
	return c, nil
}

// addHash adds a new hash to the checker.
func (c *Checker) addHash(name, value string, hashes map[string]HashFunc) (hash.Hash, error) {
	if h, present := c.hashes[name]; present {
		if err := c.validateHash(h, name, value); err != nil {
			return nil, err
		}
		c.expected[name] = append(c.expected[name], value)
		return nil, nil
	}
	hash, present := hashes[name]
	if !present {
		return nil, fmt.Errorf("Unknown hash type %s", name)
	}
	h := hash()
	if err := c.validateHash(h, name, value); err != nil {
		return nil, err
	}
	c.expected[name] = []string{value}
	c.hashes[name] = h
	return h, nil
}

// validateHash returns an error if the given string is not valid for a particular hash.
func (c *Checker) validateHash(h hash.Hash, name, value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("Invalid base64 string: %s", err)
	} else if len(decoded) != h.Size() {
		return fmt.Errorf("Value %s is not valid for hash type %s; should be %d bytes, was %d", value, name, h.Size(), len(decoded))
	}
	return nil
}

// Write implements the io.Writer interface.
// It never returns an error.
func (c *Checker) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

// Check checks the data read so far against the expected hashes.
// It returns an error if it does not match or nil on success.
func (c *Checker) Check() error {
	var msgs []string
	for name, hash := range c.hashes {
		expected := c.expected[name]
		h := hash.Sum(nil)
		value := base64.StdEncoding.EncodeToString(h)
		if !contains(expected, value) {
			hexValue := hex.EncodeToString(h)
			msgs = append(msgs, fmt.Sprintf("violated %s integrity check; was %s, expected %s (a.k.a. was %s, expected %s)", name, value, describeExpected(expected), hexValue, describeExpected(toHex(expected))))
		}
	}
	if len(msgs) != 0 {
		return fmt.Errorf("subresource integrity failed: %s", strings.Join(msgs, "; "))
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, straw := range haystack {
		if straw == needle {
			return true
		}
	}
	return false
}

func describeExpected(expected []string) string {
	if len(expected) == 1 {
		return expected[0]
	}
	return fmt.Sprintf("one of [%s]", strings.Join(expected, ", "))
}

// toHex converts a slice of base64-encoded strings to hex-encoded.
func toHex(expected []string) []string {
	ret := make([]string, len(expected))
	for i, e := range expected {
		// We know these are valid because we check it in validateHash.
		raw, _ := base64.StdEncoding.DecodeString(e)
		ret[i] = hex.EncodeToString(raw)
	}
	return ret
}

// Expected returns the expected hashes for the given hash name.
func (c *Checker) Expected(name string) []string {
	return c.expected[name]
}
