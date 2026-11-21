package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

// The malformed-header error is not an exported sentinel, so it can only be
// matched by message.
var errMalformed = errors.New("malformed authorization header")

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "valid api key",
			headers: authHeader("ApiKey secret-key-123"),
			wantKey: "secret-key-123",
		},
		{
			name: "header name lookup is case-insensitive",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("authorization", "ApiKey secret-key-123")
				return h
			}(),
			wantKey: "secret-key-123",
		},
		{
			name:    "nil headers",
			headers: nil,
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:    "no authorization header",
			headers: http.Header{"Content-Type": []string{"application/json"}},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header",
			headers: authHeader(""),
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:    "scheme without key",
			headers: authHeader("ApiKey"),
			wantErr: errMalformed,
		},
		{
			name:    "key without scheme",
			headers: authHeader("secret-key-123"),
			wantErr: errMalformed,
		},
		{
			name:    "wrong scheme",
			headers: authHeader("Bearer secret-key-123"),
			wantErr: errMalformed,
		},
		{
			name:    "scheme is case-sensitive",
			headers: authHeader("apikey secret-key-123"),
			wantErr: errMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotKey, err := auth.GetAPIKey(tt.headers)

			if !matchesErr(err, tt.wantErr) {
				t.Fatalf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}

func authHeader(value string) http.Header {
	return http.Header{"Authorization": []string{value}}
}

// matchesErr reports whether got matches want, first via errors.Is and then
// by message for errors that have no exported sentinel.
func matchesErr(got, want error) bool {
	if errors.Is(got, want) {
		return true
	}
	return got != nil && want != nil && got.Error() == want.Error()
}
