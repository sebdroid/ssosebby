package apiservice

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloudflare/cloudflare-go"
	"github.com/resend/resend-go/v2"
	"github.com/sebdroid/ssosebby/internal/flyio"
	"github.com/sebdroid/ssosebby/internal/gen/ssoready/v1/ssoreadyv1connect"
	"github.com/sebdroid/ssosebby/internal/google"
	"github.com/sebdroid/ssosebby/internal/microsoft"
	"github.com/sebdroid/ssosebby/internal/store"
)

type Service struct {
	Store                                 *store.Store
	GoogleClient                          *google.Client
	MicrosoftClient                       *microsoft.Client
	ResendClient                          *resend.Client
	EmailChallengeFrom                    string
	EmailVerificationEndpoint             string
	SAMLMetadataHTTPClient                *http.Client
	FlyioClient                           *flyio.Client
	CloudflareClient                      *cloudflare.API
	CustomAuthDomainCloudflareZoneID      string
	CustomAuthDomainCloudflareCNAMEValue  string
	CustomAdminDomainCloudflareZoneID     string
	CustomAdminDomainCloudflareCNAMEValue string
	FlyioAuthProxyAppID                   string
	FlyioAuthProxyAppCNAMEValue           string
	FlyioAdminProxyAppID                  string
	FlyioAdminProxyAppCNAMEValue          string
	S3Client                              *s3.Client
	S3PresignClient                       *s3.PresignClient
	AdminLogosS3BucketName                string
	ssoreadyv1connect.UnimplementedSSOReadyServiceHandler
}
