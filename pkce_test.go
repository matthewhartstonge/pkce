package pkce

import (
	"reflect"
	"strings"
	"testing"
)

func TestGenerateCodeChallenge(t *testing.T) {
	tests := []struct {
		name         string
		method       Method
		codeVerifier []byte
		want         string
		shouldErr    bool
		wantErr      error
	}{
		{
			name:         "should error on invalid length plain challenge",
			method:       Plain,
			codeVerifier: []byte("yolo"),
			want:         "",
			shouldErr:    true,
			wantErr:      ErrVerifierLength,
		},
		{
			name:         "should error on invalid character plain challenge",
			method:       Plain,
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen) + "!"),
			want:         "",
			shouldErr:    true,
			wantErr:      ErrVerifierCharacters,
		},
		{
			name:         "should return valid plain code challenge",
			method:       Plain,
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
			want:         strings.Repeat("a", verifierMinLen),
			shouldErr:    false,
		},
		{
			name:         "should error on invalid length S256 challenge",
			method:       S256,
			codeVerifier: []byte("yolo"),
			want:         "",
			shouldErr:    true,
			wantErr:      ErrVerifierLength,
		},
		{
			name:         "should error on invalid character S256 challenge",
			method:       S256,
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen) + "!"),
			want:         "",
			shouldErr:    true,
			wantErr:      ErrVerifierCharacters,
		},
		{
			name:         "should return a valid, compliant computed S256 challenge (len: 43)",
			method:       S256,
			codeVerifier: []byte("6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj"),
			want:         "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
			shouldErr:    false,
		},
		{
			name:         "should return a valid, compliant computed S256 challenge (len: 128)",
			method:       S256,
			codeVerifier: []byte("-1Tumv7s3D22ko6Ejt-hHX6ly1xLrvIlLesIqJS5Nw-AiSJbSCO93FbLUVFvjkJXdD5slueEFS9ub~Oe~sIcylwuav31jLFxR~QDyPQAkgR2G1QOtIJPXQODLbTK61Hs"),
			want:         "EF-_M9nkOE6p88FdlYXUHkBv96MeV56C_Dsqk9DGlxw",
			shouldErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCodeChallenge(tt.method, string(tt.codeVerifier))
			if (err != nil) != tt.shouldErr {
				t.Errorf("GenerateCodeChallenge() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("GenerateCodeChallenge() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if got != tt.want {
					t.Errorf("GenerateCodeChallenge() value length mismatch\ngot:  %v, want: %v\n", got, tt.want)
				}
			}
		})
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		shouldErr bool
		wantErr   error
	}{
		{
			name:      "should error if code verifier length is negative",
			n:         -10,
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name:      "should error if code verifier length is less than RFC 7636's minimum",
			n:         verifierMinLen - 1,
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name:      "should generate code verifier, minimum required length",
			n:         verifierMinLen,
			shouldErr: false,
		},
		{
			name:      "should generate code verifier, minimum required length",
			n:         verifierMinLen,
			shouldErr: false,
		},
		{
			name:      "should generate code verifier, length 75",
			n:         75,
			shouldErr: false,
		},
		{
			name:      "should generate code verifier, maximum required length",
			n:         verifierMaxLen,
			shouldErr: false,
		},
		{
			name:      "should error if code verifier length is greater than RFC 7636's maximum",
			n:         verifierMaxLen + 1,
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCodeVerifier(tt.n)
			if (err != nil) != tt.shouldErr {
				t.Errorf("GenerateCodeVerifier() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("GenerateCodeVerifier() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if len(got) != tt.n {
					t.Errorf("GenerateCodeVerifier() value length mismatch\ngot:  %v, want: %v\n", len(got), tt.n)
				}
			}
		})
	}
}

func TestKey_ChallengeMethod(t *testing.T) {
	tests := []struct {
		name            string
		challengeMethod Method
		want            Method
	}{
		{
			name:            "should return plain",
			challengeMethod: Plain,
			want:            Plain,
		},
		{
			name:            "should return S256",
			challengeMethod: S256,
			want:            S256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				challengeMethod: tt.challengeMethod,
			}
			if got := k.ChallengeMethod(); got != tt.want {
				t.Errorf("ChallengeMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

type codeChallengeTest struct {
	name         string
	method       Method
	codeVerifier []byte
	want         string
}

func codeChallengeTests() []codeChallengeTest {
	return []codeChallengeTest{
		{
			name:         "should return plain challenge",
			method:       Plain,
			codeVerifier: []byte("yolo"),
			want:         "yolo",
		},
		{
			name:         "should return a valid, compliant computed S256 challenge (len: 43)",
			method:       S256,
			codeVerifier: []byte("6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj"),
			want:         "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
		},
		{
			name:         "should return a valid, compliant computed S256 challenge (len: 128)",
			method:       S256,
			codeVerifier: []byte("-1Tumv7s3D22ko6Ejt-hHX6ly1xLrvIlLesIqJS5Nw-AiSJbSCO93FbLUVFvjkJXdD5slueEFS9ub~Oe~sIcylwuav31jLFxR~QDyPQAkgR2G1QOtIJPXQODLbTK61Hs"),
			want:         "EF-_M9nkOE6p88FdlYXUHkBv96MeV56C_Dsqk9DGlxw",
		},
	}
}

func TestKey_CodeChallenge(t *testing.T) {
	tests := codeChallengeTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				challengeMethod: tt.method,
				codeVerifier:    tt.codeVerifier,
			}
			if got := k.CodeChallenge(); got != tt.want {
				t.Errorf("CodeChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_CodeVerifier(t *testing.T) {
	tests := getCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				codeVerifierLen: tt.codeVerifierLen,
				codeVerifier:    tt.codeVerifier,
			}

			got := k.CodeVerifier()
			if tt.shouldGenerate {
				if len(got) != tt.codeVerifierLen {
					// test for expected generated length, as we can't perform an
					// equality check on a random value!
					t.Errorf(
						"getCodeVerifier() expected length error\ngot:  %v, want: %v",
						len(got),
						tt.codeVerifierLen,
					)
				}
			} else {
				if !reflect.DeepEqual(got, string(tt.wantCodeVerifier)) {
					t.Errorf("getCodeVerifier() = %v, want %v", got, string(tt.wantCodeVerifier))
				}
			}
		})
	}
}

type setChallengeMethodTest struct {
	name      string
	method    Method
	gotKey    *Key
	wantKey   *Key
	shouldErr bool
	wantErr   error
}

func setChallengeMethodTests() []setChallengeMethodTest {
	return []setChallengeMethodTest{
		{
			name:   "should set plain mode",
			method: Plain,
			gotKey: &Key{},
			wantKey: &Key{
				challengeMethod: Plain,
			},
			shouldErr: false,
		},
		{
			name:   "should set S256 mode",
			method: S256,
			gotKey: &Key{},
			wantKey: &Key{
				challengeMethod: S256,
			},
			shouldErr: false,
		},
		{
			name:      "should error on attempting to set a non-compliant method",
			method:    "not-a-specification-compliant-method",
			gotKey:    &Key{},
			wantKey:   &Key{},
			shouldErr: true,
			wantErr:   ErrMethodNotSupported,
		},
		{
			name:   "should not overwrite challenge method with empty method",
			method: "",
			gotKey: &Key{
				challengeMethod: S256,
			},
			wantKey: &Key{
				challengeMethod: S256,
			},
			shouldErr: true,
			wantErr:   ErrMethodNotSupported,
		},
	}
}

func TestKey_SetChallengeMethod(t *testing.T) {
	tests := setChallengeMethodTests()
	tests = append(tests, setChallengeMethodTest{
		name:      "Should error on attempting downgrade from S256 to Plain",
		method:    Plain,
		shouldErr: true,
		wantErr:   ErrMethodDowngrade,
		gotKey: &Key{
			challengeMethod: S256,
		},
		wantKey: &Key{
			challengeMethod: S256,
		},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gotKey.SetChallengeMethod(tt.method)
			if (err != nil) != tt.shouldErr {
				t.Errorf("SetChallengeMethod() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("SetChallengeMethod() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("SetChallengeMethod() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
			}
		})
	}
}

type verifyCodeVerifierTest struct {
	name             string
	method           Method
	wantCodeVerifier string
	codeVerifier     string
	codeChallenge    string
	want             bool
}

func verifyCodeVerifierTests() []verifyCodeVerifierTest {
	return []verifyCodeVerifierTest{
		{
			name:             "should not verify invalid code challenge methods",
			method:           "not-a-method",
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeChallenge:    "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			want:             false,
		},
		{
			name:             "should not verify invalid plain code verifier",
			method:           Plain,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "this-is-not-the-verifier-you-are-looking-for",
			codeChallenge:    "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			want:             false,
		},
		{
			name:             "should verify valid plain code verifier",
			method:           Plain,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeChallenge:    "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			want:             true,
		},
		{
			name:             "should not verify non-matching S256 code verifier",
			method:           S256,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "this-is-not-the-verifier-you-are-looking-for",
			codeChallenge:    "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
			want:             false,
		},
		{
			name:             "should not verify invalid length S256 code verifier",
			method:           S256,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "not-the-verifier-you-are-looking-for",
			codeChallenge:    "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
			want:             false,
		},
		{
			name:             "should not verify invalid character S256 code verifier",
			method:           S256,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "this-is-not-the-verifier-you-are-looking-for!",
			codeChallenge:    "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
			want:             false,
		},
		{
			name:             "should verify matching S256 code verifier",
			method:           S256,
			wantCodeVerifier: "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeVerifier:     "6et_m_LBa_8A-lHGANCGR0a6KATHyhr~5RU_CskUaaj",
			codeChallenge:    "1u1qURRaY4QPquG83Yu2fnyEYp4d0TLhXyj6AnaEcGQ",
			want:             true,
		},
	}
}

func TestKey_VerifyCodeVerifier(t *testing.T) {
	tests := verifyCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				challengeMethod: tt.method,
				codeVerifier:    []byte(tt.wantCodeVerifier),
			}
			if got := k.VerifyCodeVerifier(tt.codeVerifier); got != tt.want {
				t.Errorf("VerifyCodeVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

type getCodeVerifierTest struct {
	name             string
	shouldGenerate   bool
	codeVerifierLen  int
	codeVerifier     []byte
	wantCodeVerifier []byte
}

func getCodeVerifierTests() []getCodeVerifierTest {
	return []getCodeVerifierTest{
		{
			name:             "should generate code verifier, if verifier is nil",
			shouldGenerate:   true,
			codeVerifierLen:  45,
			codeVerifier:     nil,
			wantCodeVerifier: nil,
		},
		{
			name:             "should generate code verifier, if verifier is empty",
			shouldGenerate:   true,
			codeVerifierLen:  50,
			codeVerifier:     []byte{},
			wantCodeVerifier: nil,
		},
		{
			name:             "should return set code verifier",
			shouldGenerate:   false,
			codeVerifierLen:  verifierMinLen,
			codeVerifier:     []byte(strings.Repeat("a", verifierMinLen)),
			wantCodeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
		},
		{
			name:             "should not generate if a code verifier if set",
			shouldGenerate:   false,
			codeVerifierLen:  100,
			codeVerifier:     []byte(strings.Repeat("a", verifierMinLen)),
			wantCodeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
		},
	}
}

func TestKey_getCodeVerifier(t *testing.T) {
	tests := getCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				codeVerifierLen: tt.codeVerifierLen,
				codeVerifier:    tt.codeVerifier,
			}

			got := k.getCodeVerifier()
			if tt.shouldGenerate {
				if len(got) != tt.codeVerifierLen {
					// test for expected generated length, as we can't perform an
					// equality check on a random value!
					t.Errorf(
						"getCodeVerifier() expected length error\ngot:  %v, want: %v",
						len(got),
						tt.codeVerifierLen,
					)
				}
			} else {
				if !reflect.DeepEqual(got, tt.wantCodeVerifier) {
					t.Errorf("getCodeVerifier() = %v, want %v", got, tt.wantCodeVerifier)
				}
			}
		})
	}
}

type setCodeVerifierTest struct {
	name         string
	codeVerifier []byte
	gotKey       *Key
	wantKey      *Key
	shouldErr    bool
	wantErr      error
}

func setCodeVerifierTests() []setCodeVerifierTest {
	return []setCodeVerifierTest{
		{
			name:         "should not set an empty verifier",
			codeVerifier: []byte{},
			gotKey:       &Key{},
			wantKey:      &Key{},
			shouldErr:    true,
			wantErr:      ErrVerifierLength,
		},
		{
			name:         "should error configuring an invalid verifier length",
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen-1)),
			gotKey:       &Key{},
			wantKey:      &Key{},
			shouldErr:    true,
			wantErr:      ErrVerifierLength,
		},
		{
			name:         "should error configuring an invalid verifier character",
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen) + "!"),
			gotKey:       &Key{},
			wantKey:      &Key{},
			shouldErr:    true,
			wantErr:      ErrVerifierCharacters,
		},
		{
			name:         "should set a valid verifier",
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
			gotKey:       &Key{},
			wantKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen)),
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: false,
		},
		{
			name:         "should overwrite code verifier length",
			codeVerifier: []byte(strings.Repeat("a", verifierMinLen)),
			gotKey: &Key{
				codeVerifierLen: 100,
			},
			wantKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen)),
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: false,
		},
	}
}

func TestKey_setCodeVerifier(t *testing.T) {
	tests := setCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gotKey.setCodeVerifier(tt.codeVerifier)
			if (err != nil) != tt.shouldErr {
				t.Errorf("setCodeVerifier() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("setCodeVerifier() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("setCodeVerifier() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
			}
		})
	}
}

type setCodeVerifierLengthTest struct {
	name      string
	n         int
	gotKey    *Key
	wantKey   *Key
	shouldErr bool
	wantErr   error
}

func setCodeVerifierLengthTests() []setCodeVerifierLengthTest {
	return []setCodeVerifierLengthTest{
		{
			name:      "should not set a negative value",
			n:         -10,
			gotKey:    &Key{},
			wantKey:   &Key{},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name:      "should set a valid verifier length",
			n:         verifierMinLen,
			gotKey:    &Key{},
			wantKey:   &Key{codeVerifierLen: verifierMinLen},
			shouldErr: false,
		},
		{
			name:      "should not overwrite codeVerifierLen with an invalid value",
			n:         -10,
			gotKey:    &Key{codeVerifierLen: verifierMinLen},
			wantKey:   &Key{codeVerifierLen: verifierMinLen},
			shouldErr: true,
			wantErr:   ErrVerifierLength,
		},
		{
			name: "should not overwrite code verifier length if code verifier is already set",
			n:    75,
			gotKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen+1)),
				codeVerifierLen: verifierMinLen + 1,
			},
			wantKey: &Key{
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen+1)),
				codeVerifierLen: verifierMinLen + 1,
			},
			shouldErr: false,
		},
	}
}

func TestKey_setCodeVerifierLength(t *testing.T) {
	tests := setCodeVerifierLengthTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gotKey.setCodeVerifierLength(tt.n)
			if (err != nil) != tt.shouldErr {
				t.Errorf("setCodeVerifierLength() should error\ngot:  %v, want: %v\n", err, tt.shouldErr)
			}

			if tt.shouldErr {
				if tt.wantErr != err {
					t.Errorf("setCodeVerifierLength() error type not expected\ngot:  %v, want: %v\n", err, tt.wantErr)
				}
			} else {
				if !reflect.DeepEqual(tt.gotKey, tt.wantKey) {
					t.Errorf("setCodeVerifierLength() key\ngot: %v\nwant  %v\n", tt.gotKey, tt.wantKey)
				}
			}
		})
	}
}

func TestMethod_String(t *testing.T) {
	tests := []struct {
		name string
		m    Method
		want string
	}{
		{
			name: "should return a methods value",
			m:    "not-a-spec-based-method",
			want: "not-a-spec-based-method",
		},
		{
			name: "should return plain value",
			m:    Plain,
			want: "plain",
		},
		{
			name: "should return S256 value",
			m:    S256,
			want: "S256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}

	tests := []struct {
		name      string
		args      args
		wantKey   *Key
		shouldErr bool
	}{
		{
			name: "should enforce verifier minimum length and S256 as a default",
			args: args{
				opts: nil,
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: false,
		},
		{
			name: "should error with invalid code challenge method via option WithChallengeMethod",
			args: args{
				opts: []Option{
					WithChallengeMethod("not-a-method"),
				},
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: true,
		},
		{
			name: "should set code challenge method via option WithChallengeMethod",
			args: args{
				opts: []Option{
					WithChallengeMethod(Plain),
				},
			},
			wantKey: &Key{
				challengeMethod: Plain,
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: false,
		},
		{
			name: "should error with invalid code verifier via option WithCodeVerifier",
			args: args{
				opts: []Option{
					WithCodeVerifier([]byte("yolo")),
				},
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: true,
		},
		{
			name: "should set code challenge method via option WithCodeVerifier",
			args: args{
				opts: []Option{
					WithCodeVerifier([]byte(strings.Repeat("a", verifierMinLen))),
				},
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: verifierMinLen,
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen)),
			},
			shouldErr: false,
		},
		{
			name: "should error with invalid code verifier length with option WithCodeVerifierLength",
			args: args{
				opts: []Option{
					WithCodeVerifierLength(150),
				},
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: verifierMinLen,
			},
			shouldErr: true,
		},
		{
			name: "should set code verifier length with option",
			args: args{
				opts: []Option{
					WithCodeVerifierLength(100),
				},
			},
			wantKey: &Key{
				challengeMethod: S256,
				codeVerifierLen: 100,
			},
			shouldErr: false,
		},
		{
			name: "should set multiple options at once",
			args: args{
				opts: []Option{
					WithChallengeMethod(Plain),
					WithCodeVerifierLength(verifierMaxLen),
				},
			},
			wantKey: &Key{
				challengeMethod: Plain,
				codeVerifierLen: verifierMaxLen,
			},
			shouldErr: false,
		},
		{
			name: "should set all options at once",
			args: args{
				opts: []Option{
					WithChallengeMethod(Plain),
					WithCodeVerifierLength(verifierMaxLen),
					WithCodeVerifier([]byte(strings.Repeat("a", verifierMinLen+1))),
				},
			},
			wantKey: &Key{
				challengeMethod: Plain,
				codeVerifierLen: verifierMinLen + 1,
				codeVerifier:    []byte(strings.Repeat("a", verifierMinLen+1)),
			},
			shouldErr: false,
		},
		{
			name: "should error if one of the provided options is invalid",
			args: args{
				opts: []Option{
					WithChallengeMethod(Plain),
					WithCodeVerifierLength(verifierMinLen + 20),
					WithCodeVerifier([]byte(strings.Repeat("a", verifierMaxLen+1))),
				},
			},
			wantKey: &Key{
				challengeMethod: Plain,
				codeVerifierLen: verifierMinLen + 20,
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := New(tt.args.opts...)
			if (err != nil) != tt.shouldErr {
				t.Errorf("New() error = %v, shouldErr = %v", err, tt.shouldErr)
				return
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("New() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

func TestVerifyCodeVerifier(t *testing.T) {
	tests := verifyCodeVerifierTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyCodeVerifier(tt.method, tt.codeVerifier, tt.codeChallenge); got != tt.want {
				t.Errorf("VerifyCodeVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_generateCodeChallenge(t *testing.T) {
	tests := codeChallengeTests()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotOut := generateCodeChallenge(tt.method, tt.codeVerifier); gotOut != tt.want {
				t.Errorf("generateCodeChallenge() = %v, want %v", gotOut, tt.want)
			}
		})
	}
}

func Test_generateCodeVerifier(t *testing.T) {
	type args struct {
		n int
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "should generate code verifier, minimum required length",
			args: args{
				n: verifierMinLen,
			},
		},
		{
			name: "should generate code verifier, length 75",
			args: args{
				n: 75,
			},
		},
		{
			name: "should generate code verifier, maximum required length",
			args: args{
				n: verifierMaxLen,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// since these should be truly random, we aren't able to compare
			// values, but we can ensure all characters are valid and the
			// requested generation length is valid

			gotOut := generateCodeVerifier(tt.args.n)
			if len(gotOut) != tt.args.n {
				t.Errorf("generateCodeVerifier() should generate to specified length\ngot:  %v\nwant: %v\n", len(gotOut), tt.args.n)
			}
			if err := validateCodeVerifier(gotOut); err != nil {
				t.Errorf("generateCodeVerifier() should generate valid code verifiers\ngot:  %s", string(gotOut))
			}
		})
	}
}

func Test_generateCodeVerifier_randomness(t *testing.T) {
	const numHashes = 10000
	hashMap := map[string]struct{}{}

	for i := 0; i < numHashes; i++ {
		out := generateCodeVerifier(10)
		v := string(out)

		if _, ok := hashMap[v]; ok {
			t.Error("randomness check failed")
			t.FailNow()
		}

		hashMap[v] = struct{}{}
	}
}
