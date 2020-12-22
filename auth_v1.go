package swift_auth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/ncw/swift"
	"github.com/pkg/errors"
)

// v1 auth
type v1Auth struct {
	timeout time.Duration
	headers http.Header // V1 auth: the authentication headers so extensions can access them
}

// v1 Authentication - make request
func (auth *v1Auth) Request(c *swift.Connection) (*http.Request, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auth.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.AuthUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-Auth-Key", c.ApiKey)
	req.Header.Set("X-Auth-User", c.UserName)

	resp, err := doRequest(req, c.Transport)
	if err != nil {
		return nil, errors.Wrapf(err, "do auth request")
	}
	err = auth.Response(resp)
	if err != nil {
		return nil, errors.Wrapf(err, "do auth request")
	}

	return nil, nil
}

func doRequest(r *http.Request, transport http.RoundTripper) (*http.Response, error) {
	cli := http.Client{Transport: transport}
	resp, err := cli.Do(r)
	if err != nil {
		return resp, errors.Wrap(err, "do request")
	}
	defer func() {
		drainAndClose(resp.Body, &err)
		// Flush the auth connection - we don't want to keep
		// it open if keepalives were enabled
		flushKeepaliveConnections(transport)
	}()
	if err = parseHeaders(resp); err != nil {
		// Try again for a limited number of times on
		// AuthorizationFailed or BadRequest. This allows us
		// to try some alternate forms of the request
		return resp, err
	}
	return resp, nil
}

// v1 Authentication - read response
func (auth *v1Auth) Response(resp *http.Response) error {
	auth.headers = resp.Header
	return nil
}

// v1 Authentication - read storage url
func (auth *v1Auth) StorageUrl(Internal bool) string {
	storageUrl := auth.headers.Get("X-Storage-Url")
	if Internal {
		newUrl, err := url.Parse(storageUrl)
		if err != nil {
			return storageUrl
		}
		newUrl.Host = "snet-" + newUrl.Host
		storageUrl = newUrl.String()
	}
	return storageUrl
}

// v1 Authentication - read auth token
func (auth *v1Auth) Token() string {
	return auth.headers.Get("X-Auth-Token")
}

// v1 Authentication - read cdn url
func (auth *v1Auth) CdnUrl() string {
	return auth.headers.Get("X-CDN-Management-Url")
}
