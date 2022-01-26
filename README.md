# pkce

[![Go Reference](https://pkg.go.dev/badge/github.com/matthewhartstonge/pkce.svg)](https://pkg.go.dev/github.com/matthewhartstonge/pkce)
[![Go Report Card](https://goreportcard.com/badge/github.com/matthewhartstonge/pkce)](https://goreportcard.com/report/github.com/matthewhartstonge/pkce)
[![Build](https://github.com/matthewhartstonge/pkce/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/matthewhartstonge/pkce/actions/workflows/build.yml)

`pkce` implements the client side of RFC 7636 "Proof Key for Code Exchange by OAuth Public Clients" (PKCE) to enable the
generation of cryptographically secure and specification compliant code verifiers and code challenges. With :sparkles:
no external dependencies :sparkles:.

## Getting Started

`pkce` makes use of go mod, you can install it by using go get:

```shell
go get github.com/matthewhartstonge/pkce
```

## Examples

### Structs

For those that like abstractions, feel free to enjoy "safety:tm:":

```go
package main

import (
	"fmt"

	"github.com/matthewhartstonge/pkce"
)

func main() {
	// Generate a secure proof key! 
	// Make sure yo do this each time you want a new proof key - it's stateful.
	key, err := pkce.New()
	if err != nil {
		panic(err)
	}

	fmt.Println("my generated code verifier is:", key.CodeVerifier())
	fmt.Println("my generated plain code challenge is:", key.CodeChallenge())

	// Finally - on the server-side side, we can verify the received code 
	// verifier:
	receivedCodeVerifier := "#yolo-cant-verify-me-mr-mcbaggins"
	isValid := key.VerifyCodeVerifier(receivedCodeVerifier)
	fmt.Println("is the received code verifier valid?", isValid)
}
```

Okay, so that was a bit easy... But, what can I configure?!?

```go
package main

import (
	"fmt"

	"github.com/matthewhartstonge/pkce"
)

func main() {
	// Generate a ... proof key!
	key, err := pkce.New(
		// pkce.WithCodeVerifierLength enables increasing entropy for 
		// super-duper securities!
		pkce.WithCodeVerifierLength(9001),

		// pkce.WithChallengeMethod enables setting the PKCE mode, which is 
		// really code name for setting the method to "plain" for, you know, if
		// you've got a non-compliant OAuth PKCE accepting server that may 
		// require backwards compatibility. #SnarkIntended
		pkce.WithChallengeMethod(pkce.Plain),

		// pkce.WithCodeVerifier enables BYO code verifier.
		//
		// ... I hope you use a secure implementation ...
		//
		// This is mainly useful if you like the struct style of encapsulation, 
		// or if loading the verifier from a datastore.
		//
		// Using this option will disable code verifier generation, therefore 
		// `pkce.WithCodeVerifierLength` will be redundant if specified.
		pkce.WithCodeVerifier([]byte("#YOLO")),
	)
	if err != nil {
		// hah, yeah, there's gonna be an error or two...
		panic(err)
	}

	// ... otherwise, it's business as usual ...
```

### Functional

For those that like functions, you can fight against your own "to err == programmer"

```go
package main

import (
	"fmt"

	"github.com/matthewhartstonge/pkce"
)

func main() {
	// Generate a secure code verifier!
	codeVerifier, err := pkce.GenerateCodeVerifier(50)
	if err != nil {
		panic(err)
	}

	// OR, lawd forbid, you can generate and send in your own code verifier...
	//    ... don't do this ...

	// Then we can generate a code challenge based on the incoming code 
	// challenge method
	codeChallenge, err := pkce.GenerateCodeChallenge(pkce.S256, codeVerifier)
	if err != nil {
		panic(err)
	}

	fmt.Println("my manually generated code verifier is:", codeVerifier)
	fmt.Println("my manually generated code challenge is:", codeChallenge)

	// Finally - on the server-side side, we can verify the received code 
	// verifier:
	incomingCodeVerifier := "#yolo-cant-verify-me-mr-mcbaggins"
	isValid := pkce.VerifyCodeVerifier(pkce.S256, incomingCodeVerifier, codeChallenge)
	fmt.Println("is the received code verifier valid?", isValid)
}

```

## What is PKCE?

Great Question!

For more information on "Proof Key for Code Exchange (PKCE) by OAuth Public Clients" (or for some light bedtime reading)
check out the following links:

* [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
* [Auth0 - How PKCE Works](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce#how-it-works)
* [OAuth - "Protecting Apps with PKCE"](https://www.oauth.com/oauth2-servers/pkce/)
