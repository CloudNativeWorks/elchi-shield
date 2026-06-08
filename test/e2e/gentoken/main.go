// gentoken prints a signed HS256 JWT for the e2e harness.
//   gentoken -secret s -aud api -sub u1 -exp 3600   # valid 1h
//   gentoken -secret s -aud api -exp -10            # already expired
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func main() {
	secret := flag.String("secret", "s", "HMAC secret")
	aud := flag.String("aud", "", "audience")
	iss := flag.String("iss", "", "issuer")
	sub := flag.String("sub", "u1", "subject")
	exp := flag.Int("exp", 3600, "seconds until expiry (negative = already expired)")
	flag.Parse()

	claims := gojwt.MapClaims{"sub": *sub, "exp": time.Now().Add(time.Duration(*exp) * time.Second).Unix()}
	if *aud != "" {
		claims["aud"] = *aud
	}
	if *iss != "" {
		claims["iss"] = *iss
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(*secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(s)
}
