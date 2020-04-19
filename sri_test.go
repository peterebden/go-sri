package sri

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuccess(t *testing.T) {
	c, err := NewChecker("sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=")
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.NoError(t, c.Check())
}

func TestMultiSuccess(t *testing.T) {
	c, err := NewChecker(`
sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=
sha384-4QuseiT9WQ+80EDZ/MYTodasdNBTLIC/9G1XmSQDmTjTvDM8q00Vgxa9nMgwUw3j
sha512-xLpYEEen45RJnXxmFACS66+sO/1Xuo192Xq6uIarYI4uE7MZevI2pTyoKUZAFVP9tvfhJTS6YjOJcMc8ckoRkw==
`)
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.NoError(t, c.Check())
}

func TestFailure(t *testing.T) {
	c, err := NewChecker("sha256-49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=")
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.Error(t, c.Check())
}

func TestMultiFailure(t *testing.T) {
	c, err := NewChecker(`
sha256-49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=
sha384-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k
sha512-jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==
`)
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.Error(t, c.Check())
}

func TestMixedSuccess(t *testing.T) {
	// This has both successful and unsuccessful hashes which should be OK (because there is at least one good one of each type)
	c, err := NewChecker(`
sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=
sha384-4QuseiT9WQ+80EDZ/MYTodasdNBTLIC/9G1XmSQDmTjTvDM8q00Vgxa9nMgwUw3j
sha512-xLpYEEen45RJnXxmFACS66+sO/1Xuo192Xq6uIarYI4uE7MZevI2pTyoKUZAFVP9tvfhJTS6YjOJcMc8ckoRkw==
sha256-49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=
sha384-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k
sha512-jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==
`)
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.NoError(t, c.Check())
}

func TestMixedFailure(t *testing.T) {
	// This has both successful and unsuccessful hashes, but not a successful SHA512 so it should fail even though SHA384 and SHA256 are OK.
	c, err := NewChecker(`
sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=
sha384-4QuseiT9WQ+80EDZ/MYTodasdNBTLIC/9G1XmSQDmTjTvDM8q00Vgxa9nMgwUw3j
sha512-jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==
sha256-49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=
sha384-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k
sha512-jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==
`)
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.Error(t, c.Check())
}

func TestInvalidHashName(t *testing.T) {
	_, err := NewChecker(`sha1-plyJ8jPttaMEVHl2WQbzDVT4pfU=`)
	assert.Error(t, err)
}

func TestCustomHashType(t *testing.T) {
	c, err := NewCheckerForHashes("md5-IdZNPlbFer1sm3bEsO3Mpw==", map[string]HashFunc{
		"md5": md5.New,
	})
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.NoError(t, c.Check())
}

func TestSHA1(t *testing.T) {
	c, err := NewCheckerWithSHA1(`sha1-plyJ8jPttaMEVHl2WQbzDVT4pfU=`)
	assert.NoError(t, err)
	c.Write([]byte("I want a sandwich"))
	assert.NoError(t, c.Check())
}

func TestNotBase64(t *testing.T) {
	_, err := NewChecker(`sha256-wibblewibblewibble`)
	assert.Error(t, err)
}

func TestInvalidHashLength(t *testing.T) {
	// This fails because the hash is the wrong length (so it can never be a valid SHA256 hash)
	_, err := NewChecker(`sha256-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k`)
	assert.Error(t, err)
}

func TestInvalidHashLengthSecondTime(t *testing.T) {
	// As above but happens to be done in a different codepath.
	_, err := NewChecker(`sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0= sha256-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k`)
	assert.Error(t, err)
}

func TestNonsenseInput(t *testing.T) {
	_, err := NewChecker(`wibble wibble wibble`)
	assert.Error(t, err)
}

func TestNoInput(t *testing.T) {
	_, err := NewChecker(``)
	assert.Error(t, err)
}

func TestExpected(t *testing.T) {
	c, err := NewChecker(`
sha256-y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=
sha384-4QuseiT9WQ+80EDZ/MYTodasdNBTLIC/9G1XmSQDmTjTvDM8q00Vgxa9nMgwUw3j
sha512-xLpYEEen45RJnXxmFACS66+sO/1Xuo192Xq6uIarYI4uE7MZevI2pTyoKUZAFVP9tvfhJTS6YjOJcMc8ckoRkw==
sha256-49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=
sha384-ixBUOCmT6wnGpEL5AxEsAm9EdJCBj7kF099SUkvIbtB63ydFdgNgXVj784BCcJ2k
sha512-jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==
`)
	assert.NoError(t, err)
	assert.Equal(t, []string{
		"y1v31NktLrKLVp1gbS7zjWtYgDICENEw7hKLJHcw4E0=",
		"49hwASqGvw3v5oq2Pu4U2jR2Pv9KCMm2VGFAqCwEXhI=",
	}, c.Expected("sha256"))
	assert.Equal(t, []string{
		"xLpYEEen45RJnXxmFACS66+sO/1Xuo192Xq6uIarYI4uE7MZevI2pTyoKUZAFVP9tvfhJTS6YjOJcMc8ckoRkw==",
		"jt9sSgTPOFnKQWLknlJEWjBq6UaOcjZzJOwlSgaEWr1b8IfmBmOMJZ91TmrZzjbUUB211oxxKEjyOBQHeXiDoA==",
	}, c.Expected("sha512"))
	assert.Nil(t, c.Expected("md5"))
}
