package authservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sebdroid/ssosebby/internal/authn"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/saml"
	"github.com/sebdroid/ssosebby/internal/store"
	"github.com/sebdroid/ssosebby/internal/store/idformat"
)

type openidConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

func (s *Service) oauthOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := openidConfig{
		Issuer:                            fmt.Sprintf("%s/v1/oauth", s.BaseURL),
		AuthorizationEndpoint:             fmt.Sprintf("%s/v1/oauth/authorize", s.BaseURL),
		TokenEndpoint:                     fmt.Sprintf("%s/v1/oauth/token", s.BaseURL),
		JWKSURI:                           fmt.Sprintf("%s/v1/oauth/jwks", s.BaseURL),
		UserinfoEndpoint:                  fmt.Sprintf("%s/v1/oauth/userinfo", s.BaseURL),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}
	if err := json.NewEncoder(w).Encode(config); err != nil {
		panic(err)
	}
}

func (s *Service) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.URL.Query().Get("client_id")
	state := r.URL.Query().Get("state")

	// support both snake and camel case, because this makes passing "additional" parameters from libraries like
	// NextAuth.js a bit more friendly, since camel-case is the JavaScript convention
	orgID := r.URL.Query().Get("organization_id")
	if orgID == "" {
		orgID = r.URL.Query().Get("organizationId")
	}

	orgExternalID := r.URL.Query().Get("organization_external_id")
	if orgExternalID == "" {
		orgExternalID = r.URL.Query().Get("organizationExternalId")
	}

	samlConnID := r.URL.Query().Get("saml_connection_id")
	if samlConnID == "" {
		samlConnID = r.URL.Query().Get("samlConnectionId")
	}

	forceAuthnParam := r.URL.Query().Get("force_authn")
	if forceAuthnParam == "" {
		forceAuthnParam = r.URL.Query().Get("forceAuthn")
	}
	// only an explicit "false" disables forced re-authentication; absent keeps the historical default
	forceAuthn := forceAuthnParam != "false"

	slog.InfoContext(ctx, "oauth_authorize", "org_id", orgID, "org_external_id", orgExternalID, "saml_conn_id", samlConnID, "force_authn", forceAuthn)

	getClientRes, err := s.Store.AuthOAuthGetClient(ctx, &store.AuthOAuthGetClientRequest{
		SAMLOAuthClientID: clientID,
	})
	if err != nil {
		var connectErr *connect.Error
		if errors.As(err, &connectErr) && connectErr.Code() == connect.CodeInvalidArgument {
			http.Error(w, connectErr.Error(), http.StatusBadRequest)
			return
		}

		panic(fmt.Errorf("get oauth client: %w", err))
	}

	ctx = authn.NewContext(ctx, authn.ContextData{
		SAMLOAuthClient: &authn.SAMLOAuthClientData{
			AppOrgID:      getClientRes.AppOrgID,
			EnvID:         getClientRes.EnvID,
			OAuthClientID: getClientRes.SAMLOAuthClientID,
		},
	})

	dataRes, err := s.Store.AuthGetOAuthAuthorizeData(ctx, &store.AuthGetOAuthAuthorizeDataRequest{
		OrganizationID:         orgID,
		OrganizationExternalID: orgExternalID,
		SAMLConnectionID:       samlConnID,
	})
	if err != nil {
		var connectErr *connect.Error
		if errors.As(err, &connectErr) && connectErr.Code() == connect.CodeInvalidArgument {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if errors.As(err, &connectErr) && connectErr.Code() == connect.CodeFailedPrecondition {
			if connectErr.Message() == "environment OAuth redirect URI not configured, see: https://ssoready.com/docs/ssoready-concepts/saml-login-flows#environment-oauth-redirect-uri-not-configured" {
				if _, err := s.Store.UpsertNotConfiguredSAMLFlow(ctx, &store.UpsertNotConfiguredSAMLFlowRequest{
					SAMLConnectionID:                         dataRes.SAMLConnectionID,
					EnvironmentOAuthRedirectURINotConfigured: true,
				}); err != nil {
					panic(err)
				}

				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if connectErr.Message() == "saml connection is not fully configured, see: https://ssoready.com/docs/ssoready-concepts/saml-flows#saml-connection-not-fully-configured" {
				if _, err := s.Store.UpsertNotConfiguredSAMLFlow(ctx, &store.UpsertNotConfiguredSAMLFlowRequest{
					SAMLConnectionID:            dataRes.SAMLConnectionID,
					SAMLConnectionNotConfigured: true,
				}); err != nil {
					panic(err)
				}

				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		panic(fmt.Errorf("get oauth authorize data: %w", err))
	}

	slog.InfoContext(ctx, "oauth_authorize_saml_connection", "saml_connection_id", dataRes.SAMLConnectionID)

	// In the standard flow, samlFlowID is assigned by GetRedirectURL. In the OAuth flow it's assigned here because
	// there is no "get redirect url" equivalent.
	samlFlowID := idformat.SAMLFlow.Format(uuid.New())

	initRes := saml.Init(&saml.InitRequest{
		RequestID:  samlFlowID,
		SPEntityID: dataRes.SPEntityID,
		Now:        time.Now(),
		ForceAuthn: forceAuthn,
	})

	if err := s.Store.AuthUpsertOAuthAuthorizeData(ctx, &store.AuthUpsertOAuthAuthorizeDataRequest{
		State:            state,
		InitiateRequest:  initRes.InitiateRequest,
		SAMLConnectionID: dataRes.SAMLConnectionID,
		SAMLFlowID:       samlFlowID,
	}); err != nil {
		panic(fmt.Errorf("upsert oauth authorize data: %w", err))
	}

	if err := acsTemplate.Execute(w, &acsTemplateData{
		SignOnURL:   dataRes.IDPRedirectURL,
		SAMLRequest: initRes.SAMLRequest,
	}); err != nil {
		panic(fmt.Errorf("acsTemplate.Execute: %w", err))
	}
}

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type idTokenClaims struct {
	jwt.Claims

	OrganizationID         string            `json:"organizationId"`
	OrganizationExternalID string            `json:"organizationExternalId"`
	Attributes             map[string]string `json:"attributes"`
	Eppn                   string            `json:"eppn,omitempty"`
}

func (s *Service) oauthToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	getClientRes, err := s.Store.AuthOAuthGetClientWithSecret(ctx, &store.AuthOAuthGetClientWithSecretRequest{
		SAMLOAuthClientID:     clientID,
		SAMLOAuthClientSecret: clientSecret,
	})
	if err != nil {
		var connectErr *connect.Error
		if errors.As(err, &connectErr) && connectErr.Code() == connect.CodeInvalidArgument {
			http.Error(w, connectErr.Error(), http.StatusBadRequest)
			return
		}

		panic(fmt.Errorf("get oauth client: %w", err))
	}

	ctx = authn.NewContext(ctx, authn.ContextData{
		SAMLOAuthClient: &authn.SAMLOAuthClientData{
			AppOrgID:      getClientRes.AppOrgID,
			EnvID:         getClientRes.EnvID,
			OAuthClientID: getClientRes.SAMLOAuthClientID,
		},
	})

	res, err := s.Store.RedeemSAMLAccessCode(ctx, &ssoreadyv1.RedeemSAMLAccessCodeRequest{
		SamlAccessCode: r.FormValue("code"),
	})
	if err != nil {
		var samlAccessCodeNotFoundErr *store.SAMLAccessCodeNotFoundError
		if errors.As(err, &samlAccessCodeNotFoundErr) {
			http.Error(w, "saml access code not found, or already used", http.StatusNotFound)
			return
		}
		panic(err)
	}

	signerOptions := jose.SignerOptions{}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       s.OAuthIDTokenPrivateKey,
	}, signerOptions.WithType("JWT"))
	if err != nil {
		panic(err)
	}

	eppn := res.Attributes["urn:mace:dir:attribute-def:eduPersonPrincipalName"]
	if eppn == "" {
		eppn = res.Attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"]
	}

	now := time.Now()
	claims := idTokenClaims{
		Claims: jwt.Claims{
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			Issuer:   fmt.Sprintf("%s/v1/oauth", s.BaseURL),
			Audience: jwt.Audience{getClientRes.SAMLOAuthClientID},

			Subject: res.Email,
		},
		OrganizationID:         res.OrganizationId,
		OrganizationExternalID: res.OrganizationExternalId,
		Attributes:             res.Attributes,
		Eppn:                   eppn,
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}

	tokenRes := tokenResponse{
		IDToken:     idToken,
		AccessToken: idToken, // see oauthUserinfo
		TokenType:   "Bearer",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenRes); err != nil {
		panic(err)
	}
}

func (s *Service) oauthUserinfo(w http.ResponseWriter, r *http.Request) {
	// we use the id_token to also be the "access token"; this endpoint parses
	// that and writes it back

	accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	idToken, err := jwt.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	var claims idTokenClaims
	if err := idToken.Claims(&s.OAuthIDTokenPrivateKey.PublicKey, &claims); err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	userinfo := struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Eppn          string `json:"eppn,omitempty"`
	}{
		Sub:           claims.Subject,
		Email:         claims.Subject,
		EmailVerified: true,
		Eppn:          claims.Eppn,
	}

	if err := json.NewEncoder(w).Encode(userinfo); err != nil {
		panic(err)
	}
}

func (s *Service) oauthJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: &s.OAuthIDTokenPrivateKey.PublicKey,
			},
		},
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		panic(err)
	}
}
