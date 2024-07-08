package main

import (
	"fmt"
	"github.com/ncostamagna/axul_auth/auth"
	"os"
)

func main() {
	key := "12312312123"
	id := "123"
	auth, err := auth.New(key)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	token, err2 := auth.Create(id, true, 1)
	if err2 != nil {
		fmt.Println(err2)
		os.Exit(-1)
	}
	fmt.Println("token:", token)

	user, err3 := auth.Check(token)
	fmt.Println("Error:", err3)
	fmt.Println("User:", user)
}
