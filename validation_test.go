package pkce

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

func Test_validateCodeVerifier(t *testing.T) {
	type args struct {
		verifier []byte
	}

	tests := []struct {
		name      string
		args      args
		shouldErr bool
		wantErr   error
	}{
		{
			name: "should error if verifier is nil",
			args: args{
				verifier: nil,
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: "should error if verifier is empty",
			args: args{
				verifier: []byte{},
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: "should error if verifier is too short",
			args: args{
				verifier: []byte(strings.Repeat("a", verifierMinLen-1)),
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: "should error if verifier is too long",
			args: args{
				verifier: []byte(strings.Repeat("a", verifierMaxLen+1)),
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: "should error with invalid characters (ascii)",
			args: args{
				verifier: []byte(strings.Repeat("a", verifierMinLen-1) + "!"),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should error with invalid characters (utf-8)",
			args: args{
				verifier: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa💩"),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should error with invalid characters (random byte array)",
			args: args{
				verifier: randomBytes(t, 100),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should pass with a short verifier",
			args: args{
				verifier: []byte(strings.Repeat("a", verifierMinLen)),
			},
			shouldErr: false,
		},
		{
			name: "should pass with long verifier",
			args: args{
				verifier: []byte(strings.Repeat("a", verifierMaxLen)),
			},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCodeVerifier(tt.args.verifier)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateCodeVerifier() should have error\ngot:  %v\nwant: %v\n", err, tt.shouldErr)
			}
			if (err != nil) && tt.wantErr != err {
				t.Errorf("validateCodeVerifier() expected error\ngot:  %v\nwant: %v\n", err, tt.wantErr)
			}
		})
	}
}

func Test_validateVerifierLen(t *testing.T) {
	type args struct {
		n int
	}

	tests := []struct {
		name      string
		args      args
		shouldErr bool
		wantErr   error
	}{
		{
			name: "should error if value is negative",
			args: args{
				n: -1,
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: fmt.Sprintf("should error if length is smaller than min length (%d)", verifierMinLen),
			args: args{
				n: verifierMinLen - 1,
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: fmt.Sprintf("should consider min length + 1 (%d) valid", verifierMinLen+1),
			args: args{
				n: verifierMinLen + 1,
			},
			shouldErr: false,
		},
		{
			name: fmt.Sprintf("should consider max length - 1 (%d) valid", verifierMaxLen-1),
			args: args{
				n: verifierMinLen + 1,
			},
			shouldErr: false,
		},
		{
			name: fmt.Sprintf("should error if length is greater than max length (%d)", verifierMaxLen),
			args: args{
				n: verifierMaxLen + 1,
			},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVerifierLen(tt.args.n)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateVerifierLen() should have error\ngot:  %v\nwant: %v\n", err, tt.shouldErr)
			}
			if (err != nil) && tt.wantErr != err {
				t.Errorf("validateVerifierLen() expected error\ngot:  %v\nwant: %v\n", err, tt.wantErr)
			}
		})
	}
}

func Test_validateCodeVerifierCharacters(t *testing.T) {
	type args struct {
		chars []byte
	}

	tests := []struct {
		name      string
		args      args
		shouldErr bool
		wantErr   error
	}{
		{
			name: "should error with invalid characters (ascii)",
			args: args{
				chars: []byte("abc123!abc123"),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should error with invalid characters (utf-8)",
			args: args{
				chars: []byte("XÆA-Xii"),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should error with invalid characters (random byte array)",
			args: args{
				chars: randomBytes(t, 100),
			},
			shouldErr: true,
			wantErr:   ErrVerifierCharacters,
		},
		{
			name: "should pass with valid characters",
			args: args{
				chars: []byte(unreserved),
			},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCodeVerifierCharacters(tt.args.chars)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateCodeVerifierCharacters() should have error\ngot:  %v\nwant: %v\n", err, tt.shouldErr)
			}
			if (err != nil) && tt.wantErr != err {
				t.Errorf("validateCodeVerifierCharacters() expected error\ngot:  %v\nwant: %v\n", err, tt.wantErr)
			}
		})
	}
}

func Test_validVerifierChar(t *testing.T) {
	type args struct {
		c byte
	}

	type validVerifierCharTest struct {
		name string
		args args
		want bool
	}

	tests := []validVerifierCharTest{}
	for _, char := range []byte(unreserved) {
		tests = append(tests, validVerifierCharTest{
			name: fmt.Sprintf("should consider ASCII reserved character '%c' valid", char),
			args: args{
				c: char,
			},
			want: true,
		})
	}

	for _, char := range []byte("`!@#$%^&*()+={}[]|\\/:;<>,?") {
		tests = append(tests, validVerifierCharTest{
			name: fmt.Sprintf("should consider ASCII character '%c' invalid", char),
			args: args{
				c: char,
			},
			want: false,
		})
	}

	// given UTF-8 chunks overflows a byte, we can test against a possible,
	// albeit extremely weird, vector.
	for _, char := range []byte("💩🐶あ") {
		tests = append(tests, validVerifierCharTest{
			name: "should consider UTF-8 characters invalid",
			args: args{
				c: char,
			},
			want: false,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validVerifierChar(tt.args.c); got != tt.want {
				t.Errorf("validVerifierChar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func randomBytes(t *testing.T, n int) (randomBytes []byte) {
	randomBytes = make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		t.Error("unable to generate random byte stream:", err)
	}

	return
}
