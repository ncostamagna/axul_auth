package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type UserClaims struct {
	ID         string `json:"user_id"`
	Authorized bool   `json:"authorized"`
	jwt.RegisteredClaims
}

type JWT struct {
	key        string
	UserClaims UserClaims
}

type Auth interface {
	Create(id string, authorized bool, duration int64) (string, error)
	Check(token string) (*UserClaims, error)
}

// New is a function
//
// key: JWT key
func New(key string) (Auth, error) {
	if key == "" {
		return nil, ErrKeyIsRequired
	}
	return &JWT{key: key}, nil
}

// Create is a method of JWT
//
// id: is the user ID
//
// username: is the name of user
//
// duration: token expiration (in seconds)
func (j *JWT) Create(id string, authorized bool, duration int64) (string, error) {

	claims := UserClaims{
		ID:         id,
		Authorized: authorized,
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

// Check is a method of JWT
// token: is the jwt
func (j *JWT) Check(token string) (*UserClaims, error) {
	verificationToken, err := jwt.ParseWithClaims(token, &UserClaims{}, func(beforeVeritificationToken *jwt.Token) (interface{}, error) {
		if beforeVeritificationToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, ErrAlgMethod
		}
		return []byte(j.key), nil
	})

	if err != nil || !verificationToken.Valid {
		return nil, ErrInvalidAuthentication
	}

	return verificationToken.Claims.(*UserClaims), nil
}
