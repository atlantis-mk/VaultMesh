import { AsyncPipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { RouterOutlet, type Routes } from "@angular/router";
import { map } from "rxjs";
import { VaultInactive, VaultActive, GeneratorInactive, GeneratorActive, SettingsInactive, SettingsActive } from "@bitwarden/assets/svg";
import { type BottomNavigationButton } from "@bitwarden/components";
import { PopupTabNavigationComponent } from "../platform/popup/layout/popup-tab-navigation.component";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshSessionComponent } from "./session.component";

// Reuse the upstream tab template/layout without accounts, Send or persisted route state.
@Component({
  selector: "vaultmesh-popup",
  templateUrl: "../popup/tabs-v2.component.html",
  imports: [AsyncPipe, RouterOutlet, PopupTabNavigationComponent],
  providers: [VaultMeshBrowserRpcService],
  host: { class: "tw-block tw-h-full" },
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class VaultMeshPopupComponent {
  protected readonly navButtons$ = inject(VaultMeshBrowserRpcService).state$.pipe(map(state => state.status === "ready" ? [
    { label: "vault", page: "/tabs/vault", icon: VaultInactive, iconActive: VaultActive },
    { label: "generator", page: "/tabs/generator", icon: GeneratorInactive, iconActive: GeneratorActive },
    { label: "settings", page: "/tabs/settings", icon: SettingsInactive, iconActive: SettingsActive },
  ] satisfies BottomNavigationButton[] : []));
}

// Only public page names enter the URL, never IDs, drafts, searches or authorizations.
export const vaultMeshPopupRoutes: Routes = [
  { path: "", pathMatch: "full", redirectTo: "tabs/vault" },
  ...([
    ["tabs/vault", "login"], ["tabs/generator", "generator"], ["tabs/settings", "settings"],
    ["account-security", "tools"], ["vault-settings", "vault"],
  ] as const).map(([path, surface]) => ({ path, component: VaultMeshSessionComponent, data: { surface } })),
  { path: "**", redirectTo: "tabs/vault" },
];
