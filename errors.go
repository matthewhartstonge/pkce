package pkce

import (
	"errors"
	"fmt"
)

var (
	// ErrMethodDowngrade enforces compliance with RFC 7636, 7.2.
	//
	// Clients MUST NOT downgrade to "plain" after trying the "S256" method.
	// Servers that support PKCE are required to support "S256", and servers
	// that do not support PKCE will simply ignore the unknown
	// "code_verifier".  Because of this, an error when "S256" is presented
	// can only mean that the server is faulty or that a MITM attacker is
	// trying a downgrade attack.
	ErrMethodDowngrade = errors.New("clients must not downgrade to 'plain' after trying the 'S256' method")

	// ErrVerifierCharacters enforces character compliance with the unreserved
	// character set as specified in RFC 7636, 4.1.
	ErrVerifierCharacters = errors.New("code verifier must only contain unreserved characters in the set {'" + unreserved + "'}")

	// ErrVerifierLength enforces compliance with the minimum and maximum
	// lengths as specified in RFC 7636, 4.1.
	ErrVerifierLength = errors.New(fmt.Sprintf("code verifier must be between %d and %d characters long", verifierMinLen, verifierMaxLen))
)
