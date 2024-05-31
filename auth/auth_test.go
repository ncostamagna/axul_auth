package auth_test

import (
	"github.com/ncostamagna/axul_auth/auth"
	"testing"
	"time"
)

func TestAuth_CreateToken(t *testing.T) {
	t.Run("failWhenJWTDoesntHaveKey", func(t *testing.T) {
		auth, err := auth.New("")

		if auth != nil {
			t.Errorf("auth isn't nil")
		}

		if err == nil {
			t.Errorf("err is nil")
		}
	})

	t.Run("successWithoutDuration", func(t *testing.T) {
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, err2 := auth.Create("123", "nahuel", "", 0)
		if err2 != nil {
			t.Errorf("err %v", err2)
		}

		if token == "" {
			t.Errorf("token is blank")
		}

	})

	t.Run("successWithDuration", func(t *testing.T) {
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, err2 := auth.Create("123", "nahuel", "", 20)
		if err2 != nil {
			t.Errorf("err %v", err2)
		}

		if token == "" {
			t.Errorf("token is blank")
		}

	})
}

func TestAuth_AccessToken(t *testing.T) {
	t.Run("failWhenTokenIsInvalid", func(t *testing.T) {

		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		err2 := auth.Access(id, "invalid_token")
		if err2 == nil {
			t.Errorf("err is nil, must be invalid token")
		}

	})

	t.Run("failWhenUserIDIsDifferent", func(t *testing.T) {

		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, "nahuel", "", 1)
		err2 := auth.Access("other_id", token)
		if err2 == nil {
			t.Errorf("err is nil, must be invalid user id")
		}

	})

	t.Run("failWhenTokenHasExpirated", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, "nahuel", "", 1)
		time.Sleep(2 * time.Second)
		err2 := auth.Access(id, token)
		if err2 == nil {
			t.Errorf("err is nil, must be token expired")
		}

	})

	t.Run("successWithDuration", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, "nahuel", "", 1)
		err2 := auth.Access(id, token)
		if err2 != nil {
			t.Errorf("err %v", err)
		}

	})
	t.Run("successWithoutDuration", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, "nahuel", "", 0)
		err2 := auth.Access(id, token)
		if err2 != nil {
			t.Errorf("err %v", err)
		}

	})
}
