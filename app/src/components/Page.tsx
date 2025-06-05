import React from "react";
import { Outlet, useNavigate, useParams } from "react-router";
import { EnvironmentSwitcher } from "@/components/EnvironmentSwitcher";
import {
  KeyRoundIcon,
  CalendarIcon,
  LayoutGrid,
  MailIcon,
  PhoneIcon,
  UserIcon,
  EllipsisVerticalIcon,
  SettingsIcon,
  GlobeIcon,
  PaletteIcon,
  SwatchBookIcon,
} from "lucide-react";
import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import {
  signOut,
  whoami,
} from "@/gen/ssoready/v1/ssoready-SSOReadyService_connectquery";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { DropdownMenu } from "./ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export function Page() {
  const { environmentId } = useParams();
  const { data: whoamiData } = useQuery(whoami, {});

  const signOutMutation = useMutation(signOut);
  const navigate = useNavigate();
  const handleSignOut = async () => {
    await signOutMutation.mutateAsync({});
    toast("Signed out.");
    navigate(`/login`);
  };

  return (
    <div>
      <div className="h-full border-r w-72 fixed bg-white flex flex-col justify-between">
        <div className="p-2">
          <EnvironmentSwitcher />

          <div className="m-2">
            {environmentId && (
              <Link
                to={`/environments/${environmentId}`}
                className="flex gap-2 items-center p-2 hover:bg-gray-100 rounded-sm text-sm"
              >
                <LayoutGrid className="h-4 w-4" />
                <span>Overview</span>
              </Link>
            )}

            {environmentId && (
              <Link
                to={`/environments/${environmentId}/api-keys`}
                className="flex gap-2 items-center p-2 hover:bg-gray-100 rounded-sm text-sm"
              >
                <KeyRoundIcon className="h-4 w-4" />
                <span>API Keys</span>
              </Link>
            )}

            {environmentId && (
              <Link
                to={`/environments/${environmentId}/custom-domains`}
                className="flex gap-2 items-center p-2 hover:bg-gray-100 rounded-sm text-sm"
              >
                <GlobeIcon className="h-4 w-4" />
                <span>Custom Domains</span>
              </Link>
            )}

            {environmentId && (
              <Link
                to={`/environments/${environmentId}/branding`}
                className="flex gap-2 items-center p-2 hover:bg-gray-100 rounded-sm text-sm"
              >
                <SwatchBookIcon className="h-4 w-4" />
                <span>Branding</span>
              </Link>
            )}
          </div>
        </div>

        <div>
          <div className="p-2 border-t border-gray-200">
            <Link
              to={`/settings`}
              className="flex gap-2 items-center p-2 hover:bg-gray-100 rounded-sm text-sm"
            >
              <SettingsIcon className="h-4 w-4" />
              <span>Team Settings</span>
            </Link>
          </div>

          <div className="flex items-center gap-3 justify-between border-t border-gray-200 px-4 py-4">
            <div className="flex items-center gap-3 max-w-[200px] overflow-hidden">
              <Avatar className="h-9 w-9">
                <AvatarFallback>
                  <UserIcon />
                </AvatarFallback>
              </Avatar>
              <div className="grid gap-0.5 text-xs">
                <div className="font-medium truncate">
                  {whoamiData?.displayName}
                </div>
                <div className="text-gray-400 truncate">
                  {whoamiData?.email}
                </div>
              </div>
            </div>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon">
                  <EllipsisVerticalIcon className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem
                  className="cursor-pointer"
                  onClick={handleSignOut}
                >
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>
      <div className="ml-72 p-8">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
