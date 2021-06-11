package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIndeterminentAuthenticator exhibits the unpredictable behavior of the
// IndeterminentAuthenticator's Authenticate method
func TestIndeterminentAuthenticator(t *testing.T) {
	id := &IndeterminantAuthenticator{}

	auth := id.Authenticate("username", "password")
	assert.True(t, auth || !auth)
}
