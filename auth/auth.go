package auth

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type UserClaims struct {
	ID       string `json:"id"`
	UserName string `json:"username"`
	jwt.RegisteredClaims
}

type JWT struct {
	key        string
	UserClaims UserClaims
}

type Auth interface {
	Create(id, username string, duration int64) (string, error)
	Access(id, token string) error
}

// New is a function
//
// key: JWT key
func New(key string) (Auth, error) {
	return &JWT{key: key}, nil
}

// Create is a method of JWT
//
// id: is the user ID
//
// username: is the name of user
//
// duration: token expiration (in seconds)
func (j *JWT) Create(id, username string, duration int64) (string, error) {

	claims := UserClaims{
		ID:       id,
		UserName: username,
	}

	if duration != 0 {
		claims.RegisteredClaims = jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(duration) * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	ss, err := token.SignedString([]byte(j.key))
	if err != nil {
		return "", ErrSignedStringToken
	}
	return ss, nil
}

// Access is a method of JWT
//
// id: is the user ID
//
// token: is the jwt
func (j *JWT) Access(id, token string) error {

	verificationToken, err := jwt.ParseWithClaims(token, &UserClaims{}, func(beforeVeritificationToken *jwt.Token) (interface{}, error) {
		if beforeVeritificationToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, ErrAlgMethod
		}
		return []byte(j.key), nil
	})

	if err != nil || !verificationToken.Valid {
		return ErrInvalidAuthentication
	}

	user := verificationToken.Claims.(*UserClaims)
	if user.ID != id {
		return ErrInvalidAuthentication
	}

	return nil

}
