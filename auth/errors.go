package auth

import "errors"

var ErrInvalidAuthentication = errors.New("invalid authentication")
var ErrSignedStringToken = errors.New("error in SignedString token")
var ErrAlgMethod = errors.New("invalid alg method")
var ErrKeyIsRequired = errors.New("key is required")
