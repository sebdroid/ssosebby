package saml_test

import (
	"testing"
	"time"

	"github.com/sebdroid/ssosebby/internal/saml"
	"github.com/stretchr/testify/assert"
)

func TestInit_ForceAuthnTrue(t *testing.T) {
	res := saml.Init(&saml.InitRequest{
		RequestID:  "test_request_id",
		SPEntityID: "https://sp.example.com",
		Now:        time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		ForceAuthn: true,
	})

	assert.Contains(t, res.InitiateRequest, `ForceAuthn="true"`)
}

func TestInit_ForceAuthnFalseOmitsAttribute(t *testing.T) {
	res := saml.Init(&saml.InitRequest{
		RequestID:  "test_request_id",
		SPEntityID: "https://sp.example.com",
		Now:        time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		ForceAuthn: false,
	})

	// omitted entirely: per SAML 2.0 an absent ForceAuthn means false
	assert.NotContains(t, res.InitiateRequest, "ForceAuthn")
}
