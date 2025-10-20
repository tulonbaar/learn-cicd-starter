package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case 1: Valid API key
	t.Run("Valid API key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey test_api_key")

		actual, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		expected := "test_api_key"
		if actual != expected {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	// Test case 2: No authorization header
	t.Run("No authorization header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	// Test case 3: Malformed authorization header (wrong prefix)
	t.Run("Malformed authorization header - wrong prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer test_api_key")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got %v", err.Error())
		}
	})

	// Test case 4: Malformed authorization header (missing API key)
	t.Run("Malformed authorization header - missing API key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}
		if err.Error() != "malformed authorization header" {
			t.Errorf("Expected 'malformed authorization header', got %v", err.Error())
		}
	})
}
