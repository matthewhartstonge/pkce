package pkce

import (
	"fmt"
	"testing"
)

func Test_validateVerifierLen(t *testing.T) {
	type args struct {
		n int
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: fmt.Sprintf("should error if length is smaller than min length (%d)", verifierMinLen),
			args: args{
				n: verifierMinLen - 1,
			},
			wantErr: true,
		},
		{
			name: fmt.Sprintf("should consider min length + 1 (%d) valid", verifierMinLen+1),
			args: args{
				n: verifierMinLen + 1,
			},
			wantErr: false,
		},
		{
			name: fmt.Sprintf("should consider max length - 1 (%d) valid", verifierMaxLen-1),
			args: args{
				n: verifierMinLen + 1,
			},
			wantErr: false,
		},
		{
			name: fmt.Sprintf("should error if length is greater than max length (%d)", verifierMaxLen),
			args: args{
				n: verifierMaxLen + 1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateVerifierLen(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("validateVerifierLen() error = %v, wantErr %v", err, tt.wantErr)
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
			name: fmt.Sprintf("should consider reserved character '%c' valid", char),
			args: args{
				c: char,
			},
			want: true,
		})
	}

	for _, char := range []byte("`!@#$%^&*()+={}[]|\\/:;<>,?") {
		tests = append(tests, validVerifierCharTest{
			name: fmt.Sprintf("should consider character '%c' invalid", char),
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
