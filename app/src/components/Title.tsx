import { Helmet } from "react-helmet";
import React from "react";

export function Title({ title }: { title?: string }) {
  return (
    <Helmet>
      {title ? <title>{title} | SSOSebby</title> : <title>SSOSebby</title>}
    </Helmet>
  );
}
