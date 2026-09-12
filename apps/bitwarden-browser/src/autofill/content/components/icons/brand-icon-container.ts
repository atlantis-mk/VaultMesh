import { css } from "@emotion/css";
import { html } from "lit";
import { unsafeSVG } from "lit/directives/unsafe-svg.js";

import { Theme } from "@bitwarden/common/platform/enums";

import { vaultMeshIcon } from "../../../../branding/vaultmesh-icons";

export function BrandIconContainer({ iconLink }: { iconLink?: URL; theme: Theme }) {
  // The SVG is a bundled build-time asset, never page- or user-provided markup.
  const Icon = html`<div class=${brandIconContainerStyles} aria-hidden="true">${unsafeSVG(vaultMeshIcon)}</div>`;

  return iconLink ? html`<a href="${iconLink}" target="_blank" rel="noreferrer">${Icon}</a>` : Icon;
}

const brandIconContainerStyles = css`
  display: flex;
  justify-content: center;
  width: 24px;
  height: 24px;

  > svg {
    width: auto;
    height: 100%;
  }
`;
