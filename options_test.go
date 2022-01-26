package pkce

import (
	"reflect"
	"testing"
)

func TestWithChallengeMethod(t *testing.T) {
	tests := setChallengeMethodTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithChallengeMethod(tt.method)

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
	tests := setCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithCodeVerifier(tt.codeVerifier)

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
	tests := setCodeVerifierLengthTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithCodeVerifierLength(tt.n)

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
