package authservice

import (
	"testing"

	"github.com/sebdroid/ssosebby/internal/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveEmail_NameIDIsEmail(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID:         "alice@example.com",
		SubjectAttributes: map[string]string{},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "alice@example.com", email)
	assert.Equal(t, "example.com", domain)
}

func TestResolveEmail_NameIDIsEmail_IgnoresAttributes(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "alice@example.com",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail": "different@example.com",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "alice@example.com", email)
	assert.Equal(t, "example.com", domain)
}

func TestResolveEmail_PersistentNameID_FallbackToMACE(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail": "alice@surfconext.nl",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "alice@surfconext.nl", email)
	assert.Equal(t, "surfconext.nl", domain)
}

func TestResolveEmail_PersistentNameID_FallbackToOID(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:oid:0.9.2342.19200300.100.1.3": "bob@university.edu",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "bob@university.edu", email)
	assert.Equal(t, "university.edu", domain)
}

func TestResolveEmail_PersistentNameID_BothAttributesMatch(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail":   "alice@surfconext.nl",
			"urn:oid:0.9.2342.19200300.100.1.3": "alice@surfconext.nl",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "alice@surfconext.nl", email)
	assert.Equal(t, "surfconext.nl", domain)
}

func TestResolveEmail_PersistentNameID_BothAttributesMatchCaseInsensitive(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail":   "Alice@SURFconext.nl",
			"urn:oid:0.9.2342.19200300.100.1.3": "alice@surfconext.nl",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "Alice@SURFconext.nl", email)
	assert.Equal(t, "surfconext.nl", domain)
}

func TestResolveEmail_PersistentNameID_MismatchedAttributes(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail":   "alice@example.com",
			"urn:oid:0.9.2342.19200300.100.1.3": "bob@example.com",
		},
	}

	email, domain, bad := resolveEmail(res)

	require.NotNil(t, bad)
	assert.Contains(t, *bad, "mismatched")
	assert.Contains(t, *bad, "alice@example.com")
	assert.Contains(t, *bad, "bob@example.com")
	assert.Empty(t, email)
	assert.Empty(t, domain)
}

func TestResolveEmail_PersistentNameID_NoEmailAnywhere(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID:         "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{},
	}

	email, domain, bad := resolveEmail(res)

	require.NotNil(t, bad)
	assert.Equal(t, "_a3f2b8c1d4e5f6a7b8c9", *bad)
	assert.Empty(t, email)
	assert.Empty(t, domain)
}

func TestResolveEmail_PersistentNameID_AttributeIsInvalidEmail(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail": "not-an-email",
		},
	}

	email, domain, bad := resolveEmail(res)

	require.NotNil(t, bad)
	assert.Equal(t, "_a3f2b8c1d4e5f6a7b8c9", *bad)
	assert.Empty(t, email)
	assert.Empty(t, domain)
}

func TestResolveEmail_PersistentNameID_EmptyAttributeSkipped(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_a3f2b8c1d4e5f6a7b8c9",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail":   "",
			"urn:oid:0.9.2342.19200300.100.1.3": "alice@example.com",
		},
	}

	email, domain, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "alice@example.com", email)
	assert.Equal(t, "example.com", domain)
}

func TestResolveEmail_PrefersMACEOverOID(t *testing.T) {
	res := &saml.ValidateResponse{
		SubjectID: "_opaque",
		SubjectAttributes: map[string]string{
			"urn:mace:dir:attribute-def:mail":   "mace@example.com",
			"urn:oid:0.9.2342.19200300.100.1.3": "mace@example.com",
		},
	}

	email, _, bad := resolveEmail(res)

	assert.Nil(t, bad)
	assert.Equal(t, "mace@example.com", email)
}
