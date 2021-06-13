package mocks

import (
	"math/rand"
	"time"

	"github.com/trisolaria/connectulum/pkg/crypt"
	"github.com/trisolaria/connectulum/pkg/db"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type (
	authenticator100 struct{}
	authenticator50  struct{}
	authenticator0   struct{}
)

func NewAuthenticator(p int) crypt.Authenticator {
	switch p {
	case 0:
		return &authenticator0{}
	case 50:
		return &authenticator50{}
	case 100:
		return &authenticator100{}
	}
	return &authenticator0{}
}

func (a *authenticator100) Authenticate(u, p string) bool {
	return true
}

func (a *authenticator50) Authenticate(u, p string) bool {
	rand.Seed(time.Now().UnixNano())
	return rand.Float32() < 0.5
}

func (a *authenticator0) Authenticate(u, p string) bool {
	return false
}

func TrisolanData() db.Data {
	return db.Data{
		"trisolan.low":  db.RetryPolicy{MaxTimes: 2},
		"trisolan.high": db.RetryPolicy{MaxTimes: 10},
	}
}
