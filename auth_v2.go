package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ncw/swift/v2"
	"github.com/pkg/errors"
)

// v2 Authentication
type v2Auth struct {
	Auth        *v2AuthResponse
	Region      string
	timeout     time.Duration
	useApiKey   bool // if set will use API key not Password
	useApiKeyOk bool // if set won't change useApiKey any more
	notFirst    bool // set after first run
}

// v2 Authentication - make request
func (auth *v2Auth) Request(ctx context.Context, c *swift.Connection) (*http.Request, error) {
	auth.Region = c.Region
	// Toggle useApiKey if not first run and not OK yet
	if auth.notFirst && !auth.useApiKeyOk {
		auth.useApiKey = !auth.useApiKey
	}
	auth.notFirst = true
	// Create a V2 auth request for the body of the connection
	var v2i interface{}
	if !auth.useApiKey {
		// Normal swift authentication
		v2 := v2AuthRequest{}
		v2.Auth.PasswordCredentials.UserName = c.UserName
		v2.Auth.PasswordCredentials.Password = c.ApiKey
		v2.Auth.Tenant = c.Tenant
		v2.Auth.TenantId = c.TenantId
		v2i = v2
	} else {
		// Rackspace special with API Key
		v2 := v2AuthRequestRackspace{}
		v2.Auth.ApiKeyCredentials.UserName = c.UserName
		v2.Auth.ApiKeyCredentials.ApiKey = c.ApiKey
		v2.Auth.Tenant = c.Tenant
		v2.Auth.TenantId = c.TenantId
		v2i = v2
	}
	body, err := json.Marshal(v2i)
	if err != nil {
		return nil, err
	}
	url := c.AuthUrl
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "tokens"

	ctx, cancel := context.WithTimeout(ctx, auth.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := doRequest(req, c.Transport)
	if err != nil {
		return nil, errors.Wrapf(err, "do auth request")
	}
	err = auth.Response(ctx, resp)
	if err != nil {
		return nil, errors.Wrapf(err, "read response")
	}

	return nil, nil
}

// v2 Authentication - read response
func (auth *v2Auth) Response(_ context.Context, resp *http.Response) error {
	auth.Auth = new(v2AuthResponse)
	err := readJson(resp, auth.Auth)
	// If successfully read Auth then no need to toggle useApiKey any more
	if err == nil {
		auth.useApiKeyOk = true
	}
	return err
}

// Finds the Endpoint Url of "type" from the v2AuthResponse using the
// Region if set or defaulting to the first one if not
//
// Returns "" if not found
func (auth *v2Auth) endpointUrl(Type string, endpointType swift.EndpointType) string {
	for _, catalog := range auth.Auth.Access.ServiceCatalog {
		if catalog.Type == Type {
			for _, endpoint := range catalog.Endpoints {
				if auth.Region == "" || (auth.Region == endpoint.Region) {
					switch endpointType {
					case swift.EndpointTypeInternal:
						return endpoint.InternalUrl
					case swift.EndpointTypePublic:
						return endpoint.PublicUrl
					case swift.EndpointTypeAdmin:
						return endpoint.AdminUrl
					default:
						return ""
					}
				}
			}
		}
	}
	return ""
}

// v2 Authentication - read storage url
//
// If Internal is true then it reads the private (internal / service
// net) URL.
func (auth *v2Auth) StorageUrl(Internal bool) string {
	endpointType := swift.EndpointTypePublic
	if Internal {
		endpointType = swift.EndpointTypeInternal
	}
	return auth.StorageUrlForEndpoint(endpointType)
}

// v2 Authentication - read storage url
//
// Use the indicated endpointType to choose a URL.
func (auth *v2Auth) StorageUrlForEndpoint(endpointType swift.EndpointType) string {
	return auth.endpointUrl("object-store", endpointType)
}

// v2 Authentication - read auth token
func (auth *v2Auth) Token() string {
	return auth.Auth.Access.Token.Id
}

// v2 Authentication - read expires
func (auth *v2Auth) Expires() time.Time {
	t, err := time.Parse(time.RFC3339, auth.Auth.Access.Token.Expires)
	if err != nil {
		return time.Time{} // return Zero if not parsed
	}
	return t
}

// v2 Authentication - read cdn url
func (auth *v2Auth) CdnUrl() string {
	return auth.endpointUrl("rax:object-cdn", swift.EndpointTypePublic)
}

// ------------------------------------------------------------

// V2 Authentication request
//
// http://docs.openstack.org/developer/keystone/api_curl_examples.html
// http://docs.rackspace.com/servers/api/v2/cs-gettingstarted/content/curl_auth.html
// http://docs.openstack.org/api/openstack-identity-service/2.0/content/POST_authenticate_v2.0_tokens_.html
type v2AuthRequest struct {
	Auth struct {
		PasswordCredentials struct {
			UserName string `json:"username"`
			Password string `json:"password"`
		} `json:"passwordCredentials"`
		Tenant   string `json:"tenantName,omitempty"`
		TenantId string `json:"tenantId,omitempty"`
	} `json:"auth"`
}

// V2 Authentication request - Rackspace variant
//
// http://docs.openstack.org/developer/keystone/api_curl_examples.html
// http://docs.rackspace.com/servers/api/v2/cs-gettingstarted/content/curl_auth.html
// http://docs.openstack.org/api/openstack-identity-service/2.0/content/POST_authenticate_v2.0_tokens_.html
type v2AuthRequestRackspace struct {
	Auth struct {
		ApiKeyCredentials struct {
			UserName string `json:"username"`
			ApiKey   string `json:"apiKey"`
		} `json:"RAX-KSKEY:apiKeyCredentials"`
		Tenant   string `json:"tenantName,omitempty"`
		TenantId string `json:"tenantId,omitempty"`
	} `json:"auth"`
}

// V2 Authentication reply
//
// http://docs.openstack.org/developer/keystone/api_curl_examples.html
// http://docs.rackspace.com/servers/api/v2/cs-gettingstarted/content/curl_auth.html
// http://docs.openstack.org/api/openstack-identity-service/2.0/content/POST_authenticate_v2.0_tokens_.html
type v2AuthResponse struct {
	Access struct {
		ServiceCatalog []struct {
			Endpoints []struct {
				InternalUrl string
				PublicUrl   string
				AdminUrl    string
				Region      string
				TenantId    string
			}
			Name string
			Type string
		}
		Token struct {
			Expires string
			Id      string
			Tenant  struct {
				Id   string
				Name string
			}
		}
		User struct {
			DefaultRegion string `json:"RAX-AUTH:defaultRegion"`
			Id            string
			Name          string
			Roles         []struct {
				Description string
				Id          string
				Name        string
				TenantId    string
			}
		}
	}
}
