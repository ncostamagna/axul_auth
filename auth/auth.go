package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

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
	TokenAccess(id, token string) error
}

func New(key string) (Auth, error) {
	return &JWT{key: key}, nil
}

func (j *JWT) TokenAccess(id, token string) error {

	decToken, err := decrypt(token, "6470fc52afd689ca17df8667729b2c0460ce90b781a01b0010d2c4c31c85cb21")
	if err != nil {
		return ErrInvalidAuthentication
	}

	user, err := j.accessJWT(decToken)
	if err != nil || user.ID != id {
		return ErrInvalidAuthentication
	}

	return nil
}

func (j *JWT) accessJWT(token string) (*UserClaims, error) {

	verificationToken, err := jwt.ParseWithClaims(token, &UserClaims{}, func(beforeVeritificationToken *jwt.Token) (interface{}, error) {
		if beforeVeritificationToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("error in alg")
		}
		return []byte(j.key), nil

	})

	if err != nil || !verificationToken.Valid {
		return nil, ErrInvalidAuthentication
	}

	return verificationToken.Claims.(*UserClaims), nil

}

func decrypt(encryptedString string, keyString string) (string, error) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	fmt.Println(len(enc), nonceSize)
	if len(enc) < nonceSize {
		return "", errors.New("enc is lesser than nonce size")
	}
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
