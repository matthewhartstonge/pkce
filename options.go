package pkce

// Option enables variadic PKCE Key options to be configured.
type Option func(*Key) error

// WithChallengeMethod enables specifying the challenge transformation method.
// Should only be used to downgrade to plain if required.
func WithChallengeMethod(method Method) Option {
	return func(key *Key) (err error) {
		switch method {
		case Plain, S256:
			key.challengeMethod = method

		default:
			return ErrMethodNotSupported
		}

		return nil
	}
}

// WithCodeVerifier enables supplying your own code verifier. Disables code
// verifier generation.
func WithCodeVerifier(codeVerifier []byte) Option {
	return func(key *Key) (err error) {
		// validate incoming code verifier
		err = key.setCodeVerifier(codeVerifier)

		return
	}
}

// WithCodeVerifierLength enables specifying the length of the code verifier
// to be generated.
func WithCodeVerifierLength(n int) Option {
	return func(key *Key) (err error) {
		err = key.setCodeVerifierLength(n)

		return
	}
}
