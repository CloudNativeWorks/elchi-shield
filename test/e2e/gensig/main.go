// gensig prints an RFC 9421 (HTTP Message Signatures) Signature-Input and
// Signature header pair for the e2e harness, signing @method/@authority/@path
// with HMAC-SHA256. Two lines are printed: the Signature-Input value, then the
// Signature value.
//
//	gensig -secret <64+ bytes> -method GET -host api.example.com -path /sig
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/yaronf/httpsign"
)

func main() {
	secret := flag.String("secret", "", "HMAC shared secret (>= 64 bytes)")
	method := flag.String("method", "GET", "HTTP method")
	host := flag.String("host", "api.example.com", "authority")
	path := flag.String("path", "/", "request path")
	flag.Parse()

	signer, err := httpsign.NewHMACSHA256Signer([]byte(*secret),
		httpsign.NewSignConfig(), httpsign.Headers("@method", "@authority", "@path"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hr, err := http.NewRequest(*method, "http://"+*host+*path, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hr.Host = *host
	sigInput, sig, err := httpsign.SignRequest("sig1", *signer, hr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(sigInput)
	fmt.Println(sig)
}
