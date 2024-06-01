package auth

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type UserClaims struct {
	ID         string `json:"user_id"`
	UserName   string `json:"username"`
	Hash       string `json:"hash"`
	Authorized bool   `json:"authorized"`
	jwt.RegisteredClaims
}

type JWT struct {
	key        string
	UserClaims UserClaims
}

type Auth interface {
	Create(id, username, hash string, authorized bool, duration int64) (string, error)
	Access(id, token string) error
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
func (j *JWT) Create(id, username, hash string, authorized bool, duration int64) (string, error) {

	claims := UserClaims{
		ID:       id,
		UserName: username,
		Hash:     hash,
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

// Access is a method of JWT
//
// id: is the user ID
//
// token: is the jwt
// DEPRECATED
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

// Check is a method of JWT
//
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
