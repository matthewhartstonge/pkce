// Package pkce implements proof key generation defined by RFC 7636 to enable
// generation and validation of code verifiers and code challenges.
//
// "Proof Key for Code Exchange" (PKCE, pronounced "pixy") was created as a
// technique to mitigate against the authorization code interception attack.
//
// For a detailed specification of PKCE (RFC 7636) see [1].
//
// Terminology:
//   1. code verifier
//     A cryptographically random string that is used to correlate the
//     authorization request to the token request.
//
//   2. code challenge
//     A challenge derived from the code verifier that is sent in the
//     authorization request, to be verified against later.
//
//   3. code challenge method
//     A method that was used to derive code challenge.
//
//   4. Base64url Encoding
//     Base64 encoding using the URL- and filename-safe character set
//     defined in Section 5 of [RFC4648], with all trailing '='
//     characters omitted (as permitted by Section 3.2 of [RFC4648]) and
//     without the inclusion of any line breaks, whitespace, or other
//     additional characters.  (See Appendix A for notes on implementing
//     base64url encoding without padding.)
//
// [1] https://datatracker.ietf.org/doc/html/rfc7636
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

// Method specifies the code challenge transformation method that was used to
// derive the code challenge.
type Method string

// String implements Stringer.
func (m Method) String() string {
	return string(m)
}

const (
	// Plain method specifies that the code challenge has had no transformation
	// performed on the code verifier.
	//
	// code_challenge = code_verifier
	//
	// The plain transformation is for compatibility with existing
	// deployments and for constrained environments that can't use the S256
	// transformation.
	//
	Plain Method = "plain"

	// S256 method specifies that the code challenge has been transformed by
	// being hashed by SHA-256 then base64url-encoded.
	//
	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	//
	// If the client is capable of using "S256", it MUST use "S256", as
	// "S256" is Mandatory To Implement (MTI) on the server.  Clients are
	// permitted to use "plain" only if they cannot support "S256" for some
	// technical reason and know via out-of-band configuration that the
	// server supports "plain".
	S256 Method = "S256"
)

const (
	// ABNF for "code_verifier"
	// ALPHA = %x41-5A / %x61-7A
	alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// DIGIT = %x30-39
	digit = "0123456789"
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	unreserved = alpha + digit + "-._~"
)

const (
	// RFC 7636, 4.1
	verifierMinLen = 43
	verifierMaxLen = 128
)

// New returns a Proof Key
func New(opts ...Option) (key *Key, err error) {
	key = &Key{
		challengeMethod: S256,
		codeVerifierLen: verifierMinLen,
	}

	for _, opt := range opts {
		if err = opt(key); err != nil {
			return
		}
	}

	return
}

// GenerateCodeVerifier generates an RFC7636 compliant, cryptographically secure
// code verifier.
func GenerateCodeVerifier(n int) (string, error) {
	if err := validateVerifierLen(n); err != nil {
		return "", err
	}

	return string(generateCodeVerifier(n)), nil
}

// GenerateCodeChallenge takes a code verifier and method to generate a code
// challenge.
func GenerateCodeChallenge(method Method, codeVerifier string) (out string, err error) {
	in := []byte(codeVerifier)
	if err = validateCodeVerifier(in); err != nil {
		return
	}

	return generateCodeChallenge(method, in), nil
}

// VerifyCodeVerifier enables servers to verify the received code verifier.
func VerifyCodeVerifier(method Method, codeVerifier string, codeChallenge string) bool {
	// RFC 7636, 4.6.
	//
	// the server verifies it by calculating the code challenge from the
	// received "code_verifier" and comparing it with the previously associated
	// "code_challenge", after first transforming it according to the
	// "code_challenge_method" method specified by the client.
	switch method {
	case Plain:
		// If the "code_challenge_method" from Section 4.3 was "plain", they are
		// compared directly, i.e.:
		return codeVerifier == codeChallenge

	case S256:
		// If the "code_challenge_method" from Section 4.3 was "S256", the
		// received "code_verifier" is hashed by SHA-256, base64url-encoded, and
		// then compared to the "code_challenge", i.e.:
		codeVerifierChallenge, err := GenerateCodeChallenge(method, codeVerifier)
		if err != nil {
			return false
		}

		return codeVerifierChallenge == codeChallenge

	default:
		return false
	}
}

// Key provides the proof key for secure code exchange.
type Key struct {
	// challengeMethod determines the code challenge transform method to use.
	challengeMethod Method
	// codeVerifierLen provides the length of the code verifier to generate, if
	// a code verifier is not supplied on key generation.
	codeVerifierLen int
	// codeVerifier provides the code verifier data.
	codeVerifier []byte
}

// SetChallengeMethod enables upgrading code challenge generation method.
func (k *Key) SetChallengeMethod(method Method) error {
	switch method {
	case Plain, S256:
		if k.challengeMethod == S256 && method == Plain {
			return ErrMethodDowngrade
		}

		k.challengeMethod = method

	default:
		return ErrMethodNotSupported
	}

	return nil
}

// ChallengeMethod returns the configured key's method for generating a code
// challenge.
func (k *Key) ChallengeMethod() Method {
	return k.challengeMethod
}

// setCodeVerifierLength sets the length of the code verifier to be generated.
//
// If a code verifier is supplied, this setting will be ignored in favour of
// using the supplied verifier.
func (k *Key) setCodeVerifierLength(n int) error {
	if len(k.codeVerifier) > 0 {
		// Don't overwrite the set length.
		return nil
	}

	if err := validateVerifierLen(n); err != nil {
		return err
	}

	k.codeVerifierLen = n

	return nil
}

// setCodeVerifier enables setting a new code verifier.
func (k *Key) setCodeVerifier(verifier []byte) (err error) {
	if err = validateCodeVerifier(verifier); err != nil {
		return
	}

	k.codeVerifier = verifier
	k.codeVerifierLen = len(verifier)

	return
}

// CodeVerifier returns the code verifier.
func (k *Key) CodeVerifier() string {
	return string(k.getCodeVerifier())
}

// getCodeVerifier returns a code verifier. If one has not been set, it will
// generate one based on the configured verifier length.
func (k *Key) getCodeVerifier() []byte {
	if len(k.codeVerifier) == 0 {
		k.codeVerifier = generateCodeVerifier(k.codeVerifierLen)
	}

	return k.codeVerifier
}

// CodeChallenge returns the challenge for the configured code verifier.
// Will generate a verifier if nil.
func (k *Key) CodeChallenge() string {
	return generateCodeChallenge(k.ChallengeMethod(), k.getCodeVerifier())
}

// VerifyCodeVerifier provides a convenience function, for if you've loaded the
// code verifier into the key. If not, this won't really be useful to use...
func (k *Key) VerifyCodeVerifier(codeVerifier string) bool {
	return VerifyCodeVerifier(k.ChallengeMethod(), codeVerifier, k.CodeChallenge())
}

// generateCodeVerifier performs the computations required to generate a
// cryptographically random, specification compliant code verifier.
func generateCodeVerifier(n int) (out []byte) {
	unreservedLen := big.NewInt(int64(len(unreserved)))

	out = make([]byte, n)
	for i := range out {
		// ensure we use non-deterministic random ints.
		j, _ := rand.Int(rand.Reader, unreservedLen)
		out[i] = unreserved[j.Int64()]
	}

	return out
}

// generateCodeChallenge performs the transform required by the specified
// method.
func generateCodeChallenge(method Method, codeVerifier []byte) (out string) {
	if method == Plain {
		return string(codeVerifier)
	}

	s256 := sha256.New()
	s256.Write(codeVerifier)

	return base64.RawURLEncoding.EncodeToString(s256.Sum(nil))
}
