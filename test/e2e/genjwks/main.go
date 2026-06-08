// genjwks generates an RSA key, writes a one-key JWKS file for the e2e harness,
// and prints two RS256 tokens: a valid one (signed by the JWKS key) on line 1,
// and an invalid one (signed by a different key) on line 2.
//
//	genjwks -out /path/jwks.json -kid k1 -aud api
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwksJSON(pub *rsa.PublicKey, kid string) []byte {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(pub.E))
	i := 0
	for i < 7 && eb[i] == 0 {
		i++
	}
	jwk := map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b64u(pub.N.Bytes()), "e": b64u(eb[i:])}
	data, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return data
}

func sign(key *rsa.PrivateKey, kid, aud string) string {
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"sub": "u1", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return s
}

func main() {
	out := flag.String("out", "", "JWKS output file path")
	kid := flag.String("kid", "k1", "key id")
	aud := flag.String("aud", "", "audience")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out != "" {
		if err := os.WriteFile(*out, jwksJSON(&key.PublicKey, *kid), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Println(sign(key, *kid, *aud))   // valid (in the JWKS)
	fmt.Println(sign(other, *kid, *aud)) // invalid (key not in the JWKS)
}
