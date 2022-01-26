package pkce

import (
	"reflect"
	"strings"
	"testing"
)

func TestWithChallengeMethod(t *testing.T) {
	type args struct {
		method Method
	}

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr error
		gotKey      *Key
		expectedKey *Key
	}{
		{
			name: "should set plain mode",
			args: args{
				method: Plain,
			},
			gotKey: &Key{},
			expectedKey: &Key{
				challengeMethod: Plain,
			},
			wantErr: false,
		},
		{
			name: "should set S256 mode",
			args: args{
				method: S256,
			},
			gotKey: &Key{},
			expectedKey: &Key{
				challengeMethod: S256,
			},
			wantErr: false,
		},
		{
			name: "should error on attempting to set a non-compliant method",
			args: args{
				method: "not-a-specification-compliant-method",
			},
			gotKey:      &Key{},
			expectedKey: &Key{},
			wantErr:     true,
			expectedErr: ErrMethodNotSupported,
		},
		{
			name: "should not overwrite challenge method with empty method",
			args: args{
				method: "",
			},
			gotKey: &Key{
				challengeMethod: S256,
			},
			expectedKey: &Key{
				challengeMethod: S256,
			},
			wantErr:     true,
			expectedErr: ErrMethodNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithChallengeMethod(tt.args.method)

			err := opt(tt.gotKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("WithChallengeMethod() should error\ngot:  %v\nwant: %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.gotKey, tt.expectedKey) {
				t.Errorf("WithChallengeMethod() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.expectedKey)
			}
		})
	}
}

func TestWithCodeVerifier(t *testing.T) {
	type args struct {
		codeVerifier []byte
	}

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr error
		gotKey      *Key
		expectedKey *Key
	}{
		{
			name: "should not set an empty verifier",
			args: args{
				codeVerifier: []byte{},
			},
			gotKey:      &Key{},
			expectedKey: &Key{},
			wantErr:     true,
			expectedErr: ErrVerifierLength,
		},
		{
			name: "should error configuring an invalid verifier length",
			args: args{
				codeVerifier: []byte(strings.Repeat("a", verifierMinLen-1)),
			},
			gotKey:      &Key{},
			expectedKey: &Key{},
			wantErr:     true,
			expectedErr: ErrVerifierLength,
		},
		{
			name: "should error configuring an invalid verifier character",
			args: args{
				codeVerifier: []byte(strings.Repeat("a", verifierMinLen) + "!"),
			},
			gotKey:      &Key{},
			expectedKey: &Key{},
			wantErr:     true,
			expectedErr: ErrVerifierCharacters,
		},
		{
			name: "should set a valid verifier",
			args: args{
				codeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
			},
			gotKey: &Key{},
			expectedKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen)),
				codeVerifierLen: verifierMinLen,
			},
			wantErr: false,
		},
		{
			name: "should overwrite code verifier length",
			args: args{
				codeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
			},
			gotKey: &Key{
				codeVerifierLen: 100,
			},
			expectedKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen)),
				codeVerifierLen: verifierMinLen,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithCodeVerifier(tt.args.codeVerifier)

			err := opt(tt.gotKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("WithCodeVerifier() should error\ngot:  %v\nwant: %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.gotKey, tt.expectedKey) {
				t.Errorf("WithCodeVerifier() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.expectedKey)
			}
		})
	}
}

func TestWithCodeVerifierLength(t *testing.T) {
	type args struct {
		n int
	}

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr error
		gotKey      *Key
		expectedKey *Key
	}{
		{
			name: "should not set a negative value",
			args: args{
				n: -10,
			},
			gotKey:      &Key{},
			expectedKey: &Key{},
			wantErr:     true,
			expectedErr: ErrVerifierLength,
		},
		{
			name: "should set a valid verifier length",
			args: args{
				n: verifierMinLen,
			},
			gotKey:      &Key{},
			expectedKey: &Key{codeVerifierLen: verifierMinLen},
			wantErr:     false,
		},
		{
			name: "should not overwrite codeVerifierLen with an invalid value",
			args: args{
				n: -10,
			},
			gotKey:      &Key{codeVerifierLen: verifierMinLen},
			expectedKey: &Key{codeVerifierLen: verifierMinLen},
			wantErr:     true,
			expectedErr: ErrVerifierLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithCodeVerifierLength(tt.args.n)

			err := opt(tt.gotKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("WithCodeVerifierLength() should error\ngot:  %v\nwant: %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.gotKey, tt.expectedKey) {
				t.Errorf("WithCodeVerifierLength() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.expectedKey)
			}
		})
	}
}
