// gentoken prints a signed JWT for the e2e harness. It can mint valid tokens as
// well as the adversarial shapes a WAF must reject (alg:none, a disallowed
// algorithm, future not-before, missing claims).
//
//	gentoken -secret s -aud api -sub u1 -exp 3600       # valid 1h (HS256)
//	gentoken -secret s -aud api -exp -10                # already expired
//	gentoken -alg none -aud api                         # unsigned (alg:none)
//	gentoken -alg HS384 -secret s -aud api              # signed with a non-allowed alg
//	gentoken -secret s -aud api -nbf 3600               # not valid yet (nbf in future)
//	gentoken -secret s -aud api -sub ""                 # omit the sub claim
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
	sub := flag.String("sub", "u1", "subject (empty = omit the sub claim)")
	exp := flag.Int("exp", 3600, "seconds until expiry (negative = already expired)")
	nbf := flag.Int("nbf", 0, "not-before offset in seconds (positive = not valid yet)")
	alg := flag.String("alg", "HS256", "signing algorithm: HS256|HS384|none")
	flag.Parse()

	claims := gojwt.MapClaims{"exp": time.Now().Add(time.Duration(*exp) * time.Second).Unix()}
	if *sub != "" {
		claims["sub"] = *sub
	}
	if *aud != "" {
		claims["aud"] = *aud
	}
	if *iss != "" {
		claims["iss"] = *iss
	}
	if *nbf != 0 {
		claims["nbf"] = time.Now().Add(time.Duration(*nbf) * time.Second).Unix()
	}

	var method gojwt.SigningMethod
	var key any
	switch *alg {
	case "HS256":
		method, key = gojwt.SigningMethodHS256, []byte(*secret)
	case "HS384":
		method, key = gojwt.SigningMethodHS384, []byte(*secret)
	case "none":
		method, key = gojwt.SigningMethodNone, gojwt.UnsafeAllowNoneSignatureType
	default:
		fmt.Fprintln(os.Stderr, "unknown alg:", *alg)
		os.Exit(2)
	}

	s, err := gojwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(s)
}
