package session

import (
	"fmt"
	"strings"

	"github.com/trisolaria/connectulum/pkg/crypt"
)

var policyCache = make(retryPolicies)

// UserSession exposes a way to manage a user session to a specified domain.
type UserSession struct {
	idp         crypt.Authenticator
	retryPolicy retryPolicy
}

// NewUserSession initialize the IdP for this UserSession if the domain is
// supported, otherwise it returns an error.
func (s *UserSession) NewUserSession(domain string) error {
	const supportedDomain = "trisolan"
	if !strings.Contains(strings.ToLower(domain), supportedDomain) {
		return fmt.Errorf("unsupported domain for UserSession: %q", domain)
	}

	s.idp = &crypt.IndeterminantAuthenticator{}
	s.retryPolicy = policyCache.Get(domain)

	return nil
}

// Authenticate takes a username and a password as arguments, returning a boolean
// value if the provided credentials were successfully validated against the
// initialized IdP.
func (s *UserSession) Authenticate(username, password string) bool {
	ok := false
	for attempt := 0; attempt < s.retryPolicy.maxTimes && !ok; attempt++ {
		ok = s.idp.Authenticate(username, password)
	}
	if !ok {
		return false
	}
	// using the provided username and password we have successfully authenticated via this session's idp
	return true
}

// retryPolicy is a domain specific policy for how the client should perform retry attempts.
type retryPolicy struct {
	maxTimes int
}

// retryPolicies maps a domain to a retryPolicy.
type retryPolicies map[string]retryPolicy

// Set sets the retryPolicy for the specified domain.
func (rps retryPolicies) Set(domain string, rp retryPolicy) {
	rps[domain] = rp
}

// Get gets the retryPolicy for the specified domain if it exists, otherwise
// returning a default value.
func (rps retryPolicies) Get(domain string) retryPolicy {
	rp, ok := rps[domain]
	if !ok {
		return retryPolicy{maxTimes: 1}
	}
	return rp
}

func init() {
	policyCache.Set("trisolan.low", retryPolicy{maxTimes: 2})
	policyCache.Set("trisolan.high", retryPolicy{maxTimes: 10})
}
