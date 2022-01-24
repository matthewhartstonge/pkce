package pkce

// validateCodeVerifier ensures that the provided code verifier is specification
// compliant.
func validateCodeVerifier(verifier []byte) error {
	if err := validateVerifierLen(len(verifier)); err != nil {
		return err
	}

	if err := validateCodeVerifierCharacters(verifier); err != nil {
		return err
	}

	return nil
}

// validateVerifierLen ensures the length of the code verifier is within the
// bounds of the specification's declared lengths.
func validateVerifierLen(n int) error {
	if n < verifierMinLen || n > verifierMaxLen {
		return ErrVerifierLength
	}

	return nil
}

// validateCodeVerifier ensures all characters provided are in the set of
// unreserved characters.
func validateCodeVerifierCharacters(chars []byte) error {
	for _, char := range chars {
		if !validVerifierChar(char) {
			return ErrVerifierCharacters
		}
	}

	return nil
}

// validVerifierChar ensures that any bytes provided are specifically from the
// unreserved character list.
func validVerifierChar(c byte) bool {
	if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
		return true
	}

	switch c {
	case '-', '.', '_', '~':
		return true
	}

	return false
}
