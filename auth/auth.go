package auth

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	ID       string `json:"id"`
	UserName string `json:"username"`
	jwt.StandardClaims
}

type JWT struct {
	key        string
	UserClaims UserClaims
}

type Auth interface {
	Create(id, username string, duration int64) (string, error)
	Access(id, token string) error
}

func New(key string) (Auth, error) {
	return &JWT{key: key}, nil
}

func (j *JWT) Create(id, username string, duration int64) (string, error) {

	claims := UserClaims{
		ID:       id,
		UserName: username,
	}

	if duration != 0 {
		claims.StandardClaims = jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Duration(duration)).Unix(),
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	ss, err := token.SignedString([]byte(j.key))
	if err != nil {
		return "", fmt.Errorf("couldn't SignedString %w", err)
	}

	encToken := encrypt(ss, "6470fc52afd689ca17df8667729b2c0460ce90b781a01b0010d2c4c31c85cb21")
	if err != nil {
		return "", ErrInvalidAuthentication
	}
	return encToken, nil
}

func (j *JWT) Access(id, token string) error {

	decToken, err := decrypt(token, "6470fc52afd689ca17df8667729b2c0460ce90b781a01b0010d2c4c31c85cb21")
	if err != nil {
		return ErrInvalidAuthentication
	}

	verificationToken, err := jwt.ParseWithClaims(decToken, &UserClaims{}, func(beforeVeritificationToken *jwt.Token) (interface{}, error) {
		if beforeVeritificationToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("error in alg")
		}
		return []byte(j.key), nil

	})

	if err != nil || !verificationToken.Valid {
		return ErrInvalidAuthentication
	}

	user := verificationToken.Claims.(*UserClaims)
	if err != nil || user.ID != id {
		return ErrInvalidAuthentication
	}

	return nil

}
