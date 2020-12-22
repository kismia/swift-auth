package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/ncw/swift"
)

// Create a new Authenticator
//
// A hint for AuthVersion can be provided
func New(authUrl, apiKey string, authVersion int, connTimeout time.Duration) (swift.Authenticator, error) {
	if authVersion == 0 {
		if strings.Contains(authUrl, "v3") {
			authVersion = 3
		} else if strings.Contains(authUrl, "v2") {
			authVersion = 2
		} else if strings.Contains(authUrl, "v1") {
			authVersion = 1
		} else {
			return nil, fmt.Errorf("can't find authVersion in AuthUrl - set explicitly")
		}
	}

	switch authVersion {
	case 1:
		return &v1Auth{timeout: connTimeout}, nil
	case 2:
		return &v2Auth{
			// Guess as to whether using API key or
			// password it will try both eventually so
			// this is just an optimization.
			useApiKey: len(apiKey) >= 32,
			timeout:   connTimeout,
		}, nil
	case 3:
		return &v3Auth{timeout: connTimeout}, nil
	}
	return nil, fmt.Errorf("auth Version %d not supported", authVersion)
}
