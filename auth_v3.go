package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/ncw/swift/v2"
	"github.com/pkg/errors"
)

const (
	v3AuthMethodToken                 = "token"
	v3AuthMethodPassword              = "password"
	v3AuthMethodApplicationCredential = "application_credential"
	v3CatalogTypeObjectStore          = "object-store"
)

// V3 Authentication request
// http://docs.openstack.org/developer/keystone/api_curl_examples.html
// http://developer.openstack.org/api-ref-identity-v3.html
type v3AuthRequest struct {
	Auth struct {
		Identity struct {
			Methods               []string                     `json:"methods"`
			Password              *v3AuthPassword              `json:"password,omitempty"`
			Token                 *v3AuthToken                 `json:"token,omitempty"`
			ApplicationCredential *v3AuthApplicationCredential `json:"application_credential,omitempty"`
		} `json:"identity"`
		Scope *v3Scope `json:"scope,omitempty"`
	} `json:"auth"`
}

type v3Scope struct {
	Project *v3Project `json:"project,omitempty"`
	Domain  *v3Domain  `json:"domain,omitempty"`
	Trust   *v3Trust   `json:"OS-TRUST:trust,omitempty"`
}

type v3Domain struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type v3Project struct {
	Name   string    `json:"name,omitempty"`
	Id     string    `json:"id,omitempty"`
	Domain *v3Domain `json:"domain,omitempty"`
}

type v3Trust struct {
	Id string `json:"id"`
}

type v3User struct {
	Domain   *v3Domain `json:"domain,omitempty"`
	Id       string    `json:"id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Password string    `json:"password,omitempty"`
}

type v3AuthToken struct {
	Id string `json:"id"`
}

type v3AuthPassword struct {
	User v3User `json:"user"`
}

type v3AuthApplicationCredential struct {
	Id     string  `json:"id,omitempty"`
	Name   string  `json:"name,omitempty"`
	Secret string  `json:"secret,omitempty"`
	User   *v3User `json:"user,omitempty"`
}

// V3 Authentication response
type v3AuthResponse struct {
	Token struct {
		ExpiresAt string `json:"expires_at"`
		IssuedAt  string `json:"issued_at"`
		Methods   []string
		Roles     []struct {
			Id, Name string
			Links    struct {
				Self string
			}
		}

		Project struct {
			Domain struct {
				Id, Name string
			}
			Id, Name string
		}

		Catalog []struct {
			Id, Namem, Type string
			Endpoints       []struct {
				Id, Region_Id, Url, Region string
				Interface                  swift.EndpointType
			}
		}

		User struct {
			Id, Name string
			Domain   struct {
				Id, Name string
				Links    struct {
					Self string
				}
			}
		}

		Audit_Ids []string
	}
}

type v3Auth struct {
	timeout time.Duration
	Region  string
	Auth    *v3AuthResponse
	Headers http.Header
}

func (auth *v3Auth) Request(ctx context.Context, c *swift.Connection) (*http.Request, error) {
	auth.Region = c.Region

	var v3i interface{}

	v3 := v3AuthRequest{}

	if (c.ApplicationCredentialId != "" || c.ApplicationCredentialName != "") && c.ApplicationCredentialSecret != "" {
		var user *v3User

		if c.ApplicationCredentialId != "" {
			c.ApplicationCredentialName = ""
			user = &v3User{}
		}

		if user == nil && c.UserId != "" {
			// UserID could be used without the domain information
			user = &v3User{
				Id: c.UserId,
			}
		}

		if user == nil && c.UserName == "" {
			// Make sure that Username or UserID are provided
			return nil, fmt.Errorf("UserID or Name should be provided")
		}

		if user == nil && c.DomainId != "" {
			user = &v3User{
				Name: c.UserName,
				Domain: &v3Domain{
					Id: c.DomainId,
				},
			}
		}

		if user == nil && c.Domain != "" {
			user = &v3User{
				Name: c.UserName,
				Domain: &v3Domain{
					Name: c.Domain,
				},
			}
		}

		// Make sure that DomainID or DomainName are provided among Username
		if user == nil {
			return nil, fmt.Errorf("DomainID or Domain should be provided")
		}

		v3.Auth.Identity.Methods = []string{v3AuthMethodApplicationCredential}
		v3.Auth.Identity.ApplicationCredential = &v3AuthApplicationCredential{
			Id:     c.ApplicationCredentialId,
			Name:   c.ApplicationCredentialName,
			Secret: c.ApplicationCredentialSecret,
			User:   user,
		}
	} else if c.UserName == "" && c.UserId == "" {
		v3.Auth.Identity.Methods = []string{v3AuthMethodToken}
		v3.Auth.Identity.Token = &v3AuthToken{Id: c.ApiKey}
	} else {
		v3.Auth.Identity.Methods = []string{v3AuthMethodPassword}
		v3.Auth.Identity.Password = &v3AuthPassword{
			User: v3User{
				Name:     c.UserName,
				Id:       c.UserId,
				Password: c.ApiKey,
			},
		}

		var domain *v3Domain

		if c.Domain != "" {
			domain = &v3Domain{Name: c.Domain}
		} else if c.DomainId != "" {
			domain = &v3Domain{Id: c.DomainId}
		}
		v3.Auth.Identity.Password.User.Domain = domain
	}

	if v3.Auth.Identity.Methods[0] != v3AuthMethodApplicationCredential {
		if c.TrustId != "" {
			v3.Auth.Scope = &v3Scope{Trust: &v3Trust{Id: c.TrustId}}
		} else if c.TenantId != "" || c.Tenant != "" {

			v3.Auth.Scope = &v3Scope{Project: &v3Project{}}

			if c.TenantId != "" {
				v3.Auth.Scope.Project.Id = c.TenantId
			} else if c.Tenant != "" {
				v3.Auth.Scope.Project.Name = c.Tenant
				switch {
				case c.TenantDomain != "":
					v3.Auth.Scope.Project.Domain = &v3Domain{Name: c.TenantDomain}
				case c.TenantDomainId != "":
					v3.Auth.Scope.Project.Domain = &v3Domain{Id: c.TenantDomainId}
				case c.Domain != "":
					v3.Auth.Scope.Project.Domain = &v3Domain{Name: c.Domain}
				case c.DomainId != "":
					v3.Auth.Scope.Project.Domain = &v3Domain{Id: c.DomainId}
				default:
					v3.Auth.Scope.Project.Domain = &v3Domain{Name: "Default"}
				}
			}
		}
	}

	v3i = v3

	body, err := json.Marshal(v3i)

	if err != nil {
		return nil, err
	}

	url := c.AuthUrl
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "auth/tokens"

	ctx, cancel := context.WithTimeout(context.Background(), auth.timeout)
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

func (auth *v3Auth) Response(_ context.Context, resp *http.Response) error {
	auth.Auth = &v3AuthResponse{}
	auth.Headers = resp.Header
	err := readJson(resp, auth.Auth)
	return err
}

func (auth *v3Auth) endpointUrl(Type string, endpointType swift.EndpointType) string {
	for _, catalog := range auth.Auth.Token.Catalog {
		if catalog.Type == Type {
			for _, endpoint := range catalog.Endpoints {
				if endpoint.Interface == endpointType && (auth.Region == "" || (auth.Region == endpoint.Region)) {
					return endpoint.Url
				}
			}
		}
	}
	return ""
}

func (auth *v3Auth) StorageUrl(Internal bool) string {
	endpointType := swift.EndpointTypePublic
	if Internal {
		endpointType = swift.EndpointTypeInternal
	}
	return auth.StorageUrlForEndpoint(endpointType)
}

func (auth *v3Auth) StorageUrlForEndpoint(endpointType swift.EndpointType) string {
	return auth.endpointUrl("object-store", endpointType)
}

func (auth *v3Auth) Token() string {
	return auth.Headers.Get("X-Subject-Token")
}

func (auth *v3Auth) Expires() time.Time {
	t, err := time.Parse(time.RFC3339, auth.Auth.Token.ExpiresAt)
	if err != nil {
		return time.Time{} // return Zero if not parsed
	}
	return t
}

func (auth *v3Auth) CdnUrl() string {
	return ""
}

// readJson reads the response into the json type passed in
//
// Closes the response when done
func readJson(resp *http.Response, result interface{}) (err error) {
	defer drainAndClose(resp.Body, &err)
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(result)
}

// drainAndClose discards all data from rd and closes it.
// If an error occurs during Read, it is discarded.
func drainAndClose(rd io.ReadCloser, err *error) {
	if rd == nil {
		return
	}

	_, _ = io.Copy(ioutil.Discard, rd)
	cerr := rd.Close()
	if err != nil && *err == nil {
		*err = cerr
	}
}

// flushKeepaliveConnections is called to flush pending requests after an error.
func flushKeepaliveConnections(transport http.RoundTripper) {
	if tr, ok := transport.(interface {
		CloseIdleConnections()
	}); ok {
		tr.CloseIdleConnections()
	}
}

func parseHeaders(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		drainAndClose(resp.Body, nil)
		return fmt.Errorf("HTTP Error: %d: %s", resp.StatusCode, resp.Status)
	}
	return nil
}
