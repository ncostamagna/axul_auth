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

		token, err2 := auth.Create("123", true, 0)
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

		token, err2 := auth.Create("123", true, 20)
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

		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		user, err2 := auth.Check("invalid_token")
		if err2 == nil {
			t.Errorf("err is nil, must be invalid token")
		}

		if user != nil {
			t.Errorf("user is not nil, must be nil")
		}

	})

	t.Run("failWhenTokenHasExpirated", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, true, 1)
		time.Sleep(2 * time.Second)
		user, err2 := auth.Check(token)
		if err2 == nil {
			t.Errorf("err is nil, must be token expired")
		}

		if user != nil {
			t.Errorf("user is not nil, must be nil")
		}

	})

	t.Run("successWithDuration", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, true, 1)
		user, err2 := auth.Check(token)
		if err2 != nil {
			t.Errorf("err %v", err)
		}

		if user == nil {
			t.Errorf("user is nil, must be not nil")
		} else {
			if user.ID != id {
				t.Errorf("user.ID is invalid")
			}

			if user.Authorized != true {
				t.Errorf("user.Authorized is invalid")
			}
		}

	})
	t.Run("successWithoutDuration", func(t *testing.T) {
		id := "123"
		auth, err := auth.New("123456")
		if err != nil {
			t.Errorf("err %v", err)
		}

		token, _ := auth.Create(id, true, 0)
		user, err2 := auth.Check(token)
		if err2 != nil {
			t.Errorf("err %v", err)
		}

		if user == nil {
			t.Errorf("user is nil, must be not nil")
		} else {
			if user.ID != id {
				t.Errorf("user.ID is invalid")
			}

			if user.Authorized != true {
				t.Errorf("user.Authorized is invalid")
			}
		}
	})
}
