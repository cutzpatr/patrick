package session

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trisolaria/connectulum/pkg/crypt"
)

type AlwaysSuccessAuthenticator struct{}

func (as *AlwaysSuccessAuthenticator) Authenticate(u, p string) bool {
	return true
}

type AlwaysFailAuthenticator struct{}

func (as *AlwaysFailAuthenticator) Authenticate(u, p string) bool {
	return false
}

func TestUserSession_Authenticate(t *testing.T) {
	type fields struct {
		IDP      crypt.Authenticator
		maxTimes int
	}
	type args struct {
		username string
		password string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "successfully connect",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   true,
			fields: fields{IDP: &AlwaysSuccessAuthenticator{}, maxTimes: 1},
		},
		{
			name: "fail to connect to due to never trying",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   false,
			fields: fields{IDP: &AlwaysSuccessAuthenticator{}, maxTimes: 0},
		},
		{
			name: "fail to connect",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   false,
			fields: fields{IDP: &AlwaysFailAuthenticator{}, maxTimes: 100},
		},
		{
			name: "successfully connect to IndeterminantAuthenticator due to many retries",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   true,
			fields: fields{IDP: &crypt.IndeterminantAuthenticator{}, maxTimes: 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSession{
				idp:         tt.fields.IDP,
				retryPolicy: retryPolicy{maxTimes: tt.fields.maxTimes},
			}
			got := s.Authenticate(tt.args.username, tt.args.password)
			assert.Equal(t, tt.want, got, "Authenticate() = %v, want %v", got, tt.want)
		})
	}
}

func TestUserSession_NewUserSession(t *testing.T) {
	type fields struct {
		IDP crypt.Authenticator
	}
	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *UserSession
		wantErr error
	}{
		{
			name: "supported domain - 10 retries initialized in cache",
			args: args{domain: "trisolan.high"},
			want: &UserSession{
				idp:         &crypt.IndeterminantAuthenticator{},
				retryPolicy: retryPolicy{maxTimes: 10},
			},
		},
		{
			name: "supported domain - 2 retries initialized in cache",
			args: args{domain: "trisolan.low"},
			want: &UserSession{
				idp:         &crypt.IndeterminantAuthenticator{},
				retryPolicy: retryPolicy{maxTimes: 2},
			},
		},
		{
			name: "supported domain - not initialized in cache",
			args: args{domain: "trisolan.unset"},
			want: &UserSession{
				idp:         &crypt.IndeterminantAuthenticator{},
				retryPolicy: retryPolicy{maxTimes: 1},
			},
		},
		{
			name:    "unsupported domain",
			args:    args{domain: "example.com"},
			wantErr: errors.New(`unsupported domain for UserSession: "example.com"`),
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSession{
				idp: tt.fields.IDP,
			}

			err := s.NewUserSession(tt.args.domain)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.Equal(t, tt.want, s)
			}

		})
	}
}
