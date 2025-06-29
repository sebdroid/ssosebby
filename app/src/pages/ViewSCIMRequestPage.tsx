import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import React from "react";
import { Title } from "@/components/Title";
import { DocsLink } from "@/components/DocsLink";
import { useParams } from "react-router";
import { InfoTooltip } from "@/components/InfoTooltip";
import { useQuery } from "@connectrpc/connect-query";
import {
  appGetOrganization,
  appGetSCIMRequest,
} from "@/gen/ssoready/v1/ssoready-SSOReadyService_connectquery";
import {
  SCIMRequest,
  SCIMRequestHTTPMethod,
  SCIMRequestHTTPStatus,
} from "@/gen/ssoready/v1/ssoready_pb";
import moment from "moment";
import { ArrowUpFromLineIcon, OctagonX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import hljs from "highlight.js/lib/core";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Link } from "react-router-dom";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

export function ViewSCIMRequestPage() {
  const { environmentId, organizationId, scimDirectoryId, scimRequestId } =
    useParams();
  const { data: scimRequest } = useQuery(appGetSCIMRequest, {
    id: scimRequestId,
  });
  const { data: organization } = useQuery(appGetOrganization, {
    id: organizationId,
  });

  return (
    <div className="flex flex-col gap-y-8">
      <Title title="SCIM Request Log" />

      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link
                to={`/environments/${environmentId}/organizations/${organizationId}`}
              >
                {organization?.displayName || organizationId}
              </Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link
                to={`/environments/${environmentId}/organizations/${organizationId}/scim-directories/${scimDirectoryId}`}
              >
                {scimDirectoryId}
              </Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>{scimRequestId}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div className="flex flex-col space-y-1.5">
              <div className="flex gap-4">
                <CardTitle>SCIM Request Log</CardTitle>

                <span className="text-xs font-mono bg-gray-100 py-1 px-2 rounded-sm">
                  {scimRequestId}
                </span>
              </div>

              <CardDescription>
                A SCIM request log is a record of a SCIM HTTP request sent by
                your customer's identity provider to SSOSebby, and how SSOSebby
                responded.
                <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs" />
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-y-2">
            <div className="text-sm col-span-2 text-muted-foreground flex items-center gap-x-2">
              Timestamp
              <InfoTooltip>
                When the SCIM request occurred.
                <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#timestamp" />
              </InfoTooltip>
            </div>
            <div className="text-sm col-span-3">
              {scimRequest?.scimRequest &&
                moment(scimRequest.scimRequest.timestamp!.toDate()).format()}
            </div>
          </div>
        </CardContent>
      </Card>

      {scimRequest?.scimRequest?.error.case && (
        <Alert variant="destructive" className="bg-white shadow-sm">
          <OctagonX className="h-4 w-4" />
          <AlertTitle>
            This SCIM HTTP request was rejected by SSOSebby
          </AlertTitle>

          {scimRequest.scimRequest.error.case === "badBearerToken" && (
            <AlertDescription>
              <p>
                This request had an incorrect bearer token. SSOSebby could not
                authenticate that this request really came from your customer's
                identity provider.
                <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#bad-bearer-token" />
              </p>

              <p className="mt-4">
                To fix this, give your customer a{" "}
                <Link
                  to={`/environments/${environmentId}/organizations/${organizationId}`}
                  className="underline underline-offset-4"
                >
                  self-serve setup link
                </Link>{" "}
                to update their SCIM directory settings, or{" "}
                <Link
                  to={`/environments/${environmentId}/organizations/${organizationId}/scim-directories/${scimDirectoryId}`}
                  className="underline underline-offset-4"
                >
                  rotate the bearer token yourself
                </Link>{" "}
                and give it to your customer over a secure channel.
              </p>
            </AlertDescription>
          )}

          {scimRequest.scimRequest.error.case === "badUsername" && (
            <AlertDescription>
              <p>
                Your customer's identity provider set the SCIM{" "}
                <code>userName</code> to be{" "}
                <span className="font-semibold">
                  {scimRequest.scimRequest.error.value || "(No value)"}
                </span>
                , which is invalid. SSOSebby requires that SCIM usernames be
                email addresses.
                <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#bad-username" />
              </p>
            </AlertDescription>
          )}

          {scimRequest.scimRequest.error.case ===
            "emailOutsideOrganizationDomains" && (
            <AlertDescription>
              <p>
                Your customer's identity provider set the SCIM{" "}
                <code>userName</code> to be{" "}
                <span className="font-semibold">
                  {scimRequest.scimRequest.error.value}
                </span>
                , which is outside of the organization allowed domains.
                <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#email-outside-organization-domains" />
              </p>
            </AlertDescription>
          )}
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>
            HTTP Request
            <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#http-request-details" />
          </CardTitle>
          <CardDescription>
            Details about the SCIM HTTP request. This was sent from your
            customer's identity provider to SSOSebby.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {scimRequest?.scimRequest && (
            <div className="flex items-center gap-x-2">
              <SCIMRequestMethod scimRequest={scimRequest.scimRequest} />
              <SCIMRequestPath scimRequest={scimRequest.scimRequest} />
            </div>
          )}

          <div className="text-muted-foreground text-sm mt-4">Request Body</div>

          {scimRequest?.scimRequest && (
            <SCIMRequestBody scimRequest={scimRequest.scimRequest} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>
            HTTP Response
            <DocsLink to="https://ssoready.com/docs/ssoready-concepts/scim-request-logs#http-response-details" />
          </CardTitle>
          <CardDescription>
            Details about the SCIM HTTP response. This was SSOSebby's reply to
            your customer's identity provider.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {scimRequest?.scimRequest && (
            <SCIMResponseStatus scimRequest={scimRequest.scimRequest} />
          )}

          <div className="text-muted-foreground text-sm mt-4">
            Response Body
          </div>

          {scimRequest?.scimRequest && (
            <SCIMResponseBody scimRequest={scimRequest.scimRequest} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SCIMRequestMethod({ scimRequest }: { scimRequest: SCIMRequest }) {
  switch (scimRequest.httpRequestMethod) {
    case SCIMRequestHTTPMethod.SCIM_REQUEST_HTTP_METHOD_GET:
      return <Badge variant="outline">GET</Badge>;
    case SCIMRequestHTTPMethod.SCIM_REQUEST_HTTP_METHOD_POST:
      return <Badge variant="outline">POST</Badge>;
    case SCIMRequestHTTPMethod.SCIM_REQUEST_HTTP_METHOD_PUT:
      return <Badge variant="outline">PUT</Badge>;
    case SCIMRequestHTTPMethod.SCIM_REQUEST_HTTP_METHOD_PATCH:
      return <Badge variant="outline">PATCH</Badge>;
    case SCIMRequestHTTPMethod.SCIM_REQUEST_HTTP_METHOD_DELETE:
      return <Badge variant="outline">DELETE</Badge>;
  }
}

function SCIMRequestPath({ scimRequest }: { scimRequest: SCIMRequest }) {
  const prefix = `/v1/scim/${scimRequest.scimDirectoryId}`;
  return (
    <span className="text-sm text-muted-foreground">
      {scimRequest.httpRequestUrl.substring(prefix.length)}
    </span>
  );
}

function SCIMRequestBody({ scimRequest }: { scimRequest: SCIMRequest }) {
  return (
    <div className="mt-2">
      {Object.keys(scimRequest.httpRequestBody!.fields).length === 0 ? (
        <span className="text-sm">No request body</span>
      ) : (
        <div className="text-xs font-mono bg-gray-100 py-2 px-2 rounded-sm max-w-full overflow-auto">
          <code>
            <pre
              dangerouslySetInnerHTML={{
                __html: hljs.highlight(
                  JSON.stringify(scimRequest.httpRequestBody!.fields, null, 4),
                  {
                    language: "json",
                  },
                ).value,
              }}
            />
          </code>
        </div>
      )}
    </div>
  );
}

function SCIMResponseStatus({ scimRequest }: { scimRequest: SCIMRequest }) {
  const [code, message] = {
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_UNSPECIFIED]: ["", ""],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_200]: ["200", "OK"],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_201]: ["201", "Created"],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_204]: ["204", "No Content"],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_400]: [
      "400",
      "Bad Request",
    ],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_401]: [
      "401",
      "Unauthorized",
    ],
    [SCIMRequestHTTPStatus.SCIM_REQUEST_HTTP_STATUS_404]: ["404", "Not Found"],
  }[scimRequest.httpResponseStatus];

  return (
    <div className="flex items-center gap-x-2">
      <Badge variant="outline">{code}</Badge>
      <span className="text-sm text-muted-foreground">{message}</span>
    </div>
  );
}

function SCIMResponseBody({ scimRequest }: { scimRequest: SCIMRequest }) {
  return (
    <div className="mt-2">
      {Object.keys(scimRequest.httpResponseBody!.fields).length === 0 ? (
        <span className="text-sm">No response body</span>
      ) : (
        <div className="text-xs font-mono bg-gray-100 py-2 px-2 rounded-sm max-w-full overflow-auto">
          <code>
            <pre
              dangerouslySetInnerHTML={{
                __html: hljs.highlight(
                  JSON.stringify(scimRequest.httpResponseBody!.fields, null, 4),
                  {
                    language: "json",
                  },
                ).value,
              }}
            />
          </code>
        </div>
      )}
    </div>
  );
}
