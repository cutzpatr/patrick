/*
	Package crypt provides cryptographic primitives for Trisolian domains.

	Note that these primitives ONLY apply to Trisolan domains, and are
	considered unsafe for non-Trisolian applications.
*/
package crypt

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Authenticator indicates the ability to determine whether a given username and
// password combination are valid or not.
type Authenticator interface {
	Authenticate(u, p string) bool
}

// IndeterminantAuthenticator will expose the ability to authenticate in an
// indeterminant way, specific to the special needs of the Trisolarian domain.
type IndeterminantAuthenticator struct {
}

// Authenticate takes a username and a password as arguments, returning a boolean
// value at random, as required for the uncertainty heuristics specific to the
// Trisolarian domain. It is not valid, applicable, or safe for non-Trisolarian
// applications.
func (ia *IndeterminantAuthenticator) Authenticate(u, p string) bool {
	return rand.Float32() < 0.5
}
