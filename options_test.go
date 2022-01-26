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
			if (err != nil) != tt.shouldErr {
				t.Errorf("WithChallengeMethod() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("WithChallengeMethod() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("WithChallengeMethod() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
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
			if (err != nil) != tt.shouldErr {
				t.Errorf("WithCodeVerifier() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("WithCodeVerifier() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("WithCodeVerifier() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
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
			if (err != nil) != tt.shouldErr {
				t.Errorf("WithCodeVerifierLength() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("WithCodeVerifierLength() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("WithCodeVerifierLength() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
			}
		})
	}
}
