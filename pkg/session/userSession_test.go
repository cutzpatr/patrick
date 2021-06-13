package session

import (
	"github.com/trisolaria/connectulum/pkg/db"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trisolaria/connectulum/mocks"
	"github.com/trisolaria/connectulum/pkg/crypt"
)

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
			fields: fields{IDP: mocks.NewAuthenticator(100), maxTimes: 1},
		},
		{
			name: "fail to connect to due to never trying",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   false,
			fields: fields{IDP: mocks.NewAuthenticator(100), maxTimes: 0},
		},
		{
			name: "fail to connect",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   false,
			fields: fields{IDP: mocks.NewAuthenticator(0), maxTimes: 100},
		},
		{
			name: "successfully connect to IndeterminantAuthenticator via many retries",
			args: args{
				username: "user1",
				password: "pass123",
			},
			want:   true,
			fields: fields{IDP: mocks.NewAuthenticator(50), maxTimes: 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UserSession{
				idp:    tt.fields.IDP,
				policy: db.RetryPolicy{MaxTimes: tt.fields.maxTimes},
			}
			got := s.Authenticate(tt.args.username, tt.args.password)
			assert.Equal(t, tt.want, got, "Authenticate() = %v, want %v", got, tt.want)
		})
	}
}

func TestUserSession_NewUserSession(t *testing.T) {

	defaultAuth := mocks.NewAuthenticator(50)
	defaultDB := mocks.TrisolanData()

	type fields struct {
		idp *crypt.Authenticator
		db  *db.Data
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
			fields: fields{
				idp: &defaultAuth,
				db:  &defaultDB,
			},
			want: &UserSession{
				idp:    defaultAuth,
				policy: db.RetryPolicy{MaxTimes: 10},
			},
		},
		{
			name: "supported domain - 2 retries initialized in cache",
			args: args{domain: "trisolan.low"},
			fields: fields{
				idp: &defaultAuth,
				db:  &defaultDB,
			},
			want: &UserSession{
				idp:    defaultAuth,
				policy: db.RetryPolicy{MaxTimes: 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			s, err := NewUserSession(tt.fields.idp, tt.fields.db, tt.args.domain)
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
