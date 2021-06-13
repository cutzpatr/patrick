package main

import (
	"github.com/trisolaria/connectulum/mocks"
	"github.com/trisolaria/connectulum/pkg/session"
	"log"
	"time"
)

func main() {

	idp := mocks.NewAuthenticator(50)
	db := mocks.TrisolanData()

	s, err := session.NewUserSession(&idp, &db, "")
	if err != nil {
		log.Fatalf("failed to initialize NewUserSession: %+v", err)
	}

	username := "user1"
	ok := s.Authenticate(username, "pass1")
	log.Println(time.Now(), "Authenticate", username, ok)
}
