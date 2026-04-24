import React, { useCallback, useState } from "react";
import { useParams } from "react-router";
import { useInfiniteQuery, useQuery } from "@connectrpc/connect-query";
import {
  adminGetSAMLConnection,
  adminListSAMLFlows,
  adminUpdateSAMLConnection,
} from "@/gen/ssoready/v1/ssoready-SSOReadyService_connectquery";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CogIcon } from "lucide-react";
import { Link } from "react-router-dom";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import moment from "moment";
import { z } from "zod";
import {
  SAMLConnection,
  SAMLFlowStatus,
} from "@/gen/ssoready/v1/ssoready_pb";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { createConnectQueryKey, useMutation } from "@connectrpc/connect-query";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { useQueryClient } from "@tanstack/react-query";
import { Switch } from "@/components/ui/switch";
import { LayoutMain } from "@/components/Layout";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Helmet } from "react-helmet";
import { useTitle } from "@/useTitle";

export function ViewSAMLConnectionPage() {
  const { samlConnectionId } = useParams();
  if (!samlConnectionId) return null;

  const { data: samlConnection } = useQuery(adminGetSAMLConnection, {
    id: samlConnectionId,
  });

  const {
    data: listFlowsResponses,
    fetchNextPage,
    hasNextPage,
  } = useInfiniteQuery(
    adminListSAMLFlows,
    { samlConnectionId, pageToken: "" },
    {
      pageParamKey: "pageToken",
      getNextPageParam: (lastPage: { nextPageToken: string }) =>
        lastPage.nextPageToken || undefined,
    },
  );

  const title = useTitle("SAML Connection");

  return (
    <LayoutMain>
      <Helmet>
        <title>{title}</title>
      </Helmet>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div className="flex flex-col space-y-1.5">
              <div className="flex gap-4">
                <CardTitle>SAML Connection</CardTitle>

                <span className="text-xs font-mono bg-gray-100 py-1 px-2 rounded-sm">
                  {samlConnectionId}
                </span>
              </div>
            </div>

            <div>
              {samlConnection?.samlConnection && (
                <EditSAMLConnectionAlertDialog
                  samlConnection={samlConnection.samlConnection}
                />
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent>
          <div className="grid grid-cols-4 gap-y-2">
            <div className="text-sm col-span-1 text-muted-foreground">
              Primary
            </div>
            <div className="text-sm col-span-3">
              {samlConnection?.samlConnection?.primary ? "Yes" : "No"}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Service Provider Configuration</CardTitle>
          <CardDescription>
            The configuration here is assigned automatically. These settings
            need to be inputted into your Identity Provider.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-y-2 items-center">
            <div className="text-sm col-span-1 text-muted-foreground">
              Assertion Consumer Service (ACS) URL
            </div>
            <div className="text-sm col-span-3">
              {samlConnection?.samlConnection?.spAcsUrl}
            </div>

            <div className="text-sm col-span-1 text-muted-foreground">
              SP Entity ID
            </div>
            <div className="text-sm col-span-3">
              <div className="text-sm col-span-3">
                {samlConnection?.samlConnection?.spEntityId}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <div className="flex justify-between items-center">
            <div className="flex flex-col space-y-1.5">
              <CardTitle>Identity Provider Configuration</CardTitle>
              <CardDescription>
                The configuration here is assigned by your Identity Provider.
                These settings need to copied from your Identity Provider into
                here.
              </CardDescription>
            </div>

            <Button asChild variant="outline">
              <Link to={`/saml/saml-connections/${samlConnectionId}/setup`}>
                <CogIcon className="inline h-4 w-4 mr-2" />
                Setup
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-y-2 items-center">
            <div className="text-sm col-span-1 text-muted-foreground">
              IDP Entity ID
            </div>
            <div className="text-sm col-span-3">
              {samlConnection?.samlConnection?.idpEntityId}
            </div>
            <div className="text-sm col-span-1 text-muted-foreground">
              Redirect URL
            </div>
            <div className="text-sm col-span-3">
              {samlConnection?.samlConnection?.idpRedirectUrl}
            </div>
          </div>

          <Collapsible className="mt-1.5">
            <CollapsibleTrigger className="text-sm text-muted-foreground">
              Certificate (click to show)
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="bg-black rounded-lg px-6 py-4 mt-4 inline-block">
                <code className="text-sm text-white">
                  <pre>{samlConnection?.samlConnection?.idpCertificate}</pre>
                </code>
              </div>
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      </Card>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>SAML Login Flows</CardTitle>
          <CardDescription>
            SAML login flows from this connection are listed here.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>User Email</TableHead>
              </TableRow>
            </TableHeader>

            <TableBody>
              {listFlowsResponses?.pages
                ?.flatMap((page) => page.samlFlows)
                ?.map((flow) => (
                  <TableRow key={flow.id}>
                    <TableCell className="max-w-[200px] truncate">
                      <Link
                        to={`/saml/saml-connections/${samlConnectionId}/flows/${flow.id}`}
                        className="underline underline-offset-4 decoration-muted-foreground"
                      >
                        {flow.id}
                      </Link>
                    </TableCell>
                    <TableCell>
                      {moment(flow.createTime!.toDate()).format()}
                    </TableCell>
                    <TableCell>
                      {flow.status ===
                        SAMLFlowStatus.SAML_FLOW_STATUS_IN_PROGRESS && (
                        <Badge variant="secondary">In progress</Badge>
                      )}
                      {flow.status ===
                        SAMLFlowStatus.SAML_FLOW_STATUS_FAILED && (
                        <Badge variant="destructive">Failed</Badge>
                      )}
                      {flow.status ===
                        SAMLFlowStatus.SAML_FLOW_STATUS_SUCCEEDED && (
                        <Badge>Succeeded</Badge>
                      )}
                    </TableCell>
                    <TableCell>{flow.email}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>

          {hasNextPage && (
            <Button variant="secondary" onClick={() => fetchNextPage()}>
              Load more
            </Button>
          )}
        </CardContent>
      </Card>
    </LayoutMain>
  );
}

const FormSchema = z.object({
  primary: z.boolean(),
});

function EditSAMLConnectionAlertDialog({
  samlConnection,
}: {
  samlConnection: SAMLConnection;
}) {
  const form = useForm<z.infer<typeof FormSchema>>({
    resolver: zodResolver(FormSchema),
    defaultValues: {
      primary: samlConnection.primary,
    },
  });

  const [open, setOpen] = useState(false);
  const updateSAMLConnectionMutation = useMutation(adminUpdateSAMLConnection);
  const queryClient = useQueryClient();
  const handleSubmit = useCallback(
    async (values: z.infer<typeof FormSchema>, e: any) => {
      e.preventDefault();
      await updateSAMLConnectionMutation.mutateAsync({
        samlConnection: {
          id: samlConnection.id,
          primary: values.primary,
          idpEntityId: samlConnection.idpEntityId,
          idpRedirectUrl: samlConnection.idpRedirectUrl,
          idpCertificate: samlConnection.idpCertificate,
        },
      });

      await queryClient.invalidateQueries({
        queryKey: createConnectQueryKey(adminGetSAMLConnection, {
          id: samlConnection.id,
        }),
      });

      setOpen(false);
    },
    [setOpen, samlConnection, updateSAMLConnectionMutation, queryClient],
  );

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button variant="outline">Edit</Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(handleSubmit)}>
            <AlertDialogHeader>
              <AlertDialogTitle>Edit SAML connection</AlertDialogTitle>
            </AlertDialogHeader>

            <div className="my-4 space-y-4">
              <FormField
                control={form.control}
                name="primary"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Primary</FormLabel>
                    <FormControl className="block">
                      <Switch
                        name={field.name}
                        id={field.name}
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <FormDescription>
                      Whether this is the preferred SAML connection to use by
                      default.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <Button type="submit">Save</Button>
            </AlertDialogFooter>
          </form>
        </Form>
      </AlertDialogContent>
    </AlertDialog>
  );
}

