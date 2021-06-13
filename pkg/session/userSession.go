package session

import (
	"fmt"
	"github.com/trisolaria/connectulum/pkg/crypt"
	"github.com/trisolaria/connectulum/pkg/db"
)

// UserSession exposes a way to manage a user session to a specified domain.
type UserSession struct {
	idp    crypt.Authenticator
	policy db.RetryPolicy
}

// NewUserSession initialize the IdP for this UserSession if the domain is
// supported, otherwise it returns an error.
func NewUserSession(idp *crypt.Authenticator, db *db.Data, domain string) (*UserSession, error) {

	if idp == nil {
		return nil, fmt.Errorf("idp is nil")
	}

	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}

	s := &UserSession{
		idp:    *idp,
		policy: db.Get(domain),
	}

	return s, nil
}

// Authenticate takes a username and a password as arguments, returning a boolean
// value if the provided credentials were successfully validated against the
// initialized IdP.
func (s *UserSession) Authenticate(username, password string) bool {
	ok := false
	for attempt := 0; attempt < s.policy.MaxTimes && !ok; attempt++ {
		ok = s.idp.Authenticate(username, password)
	}
	if !ok {
		return false
	}
	// using the provided username and password we have successfully
	// authenticated via this session's idp
	return true
}
