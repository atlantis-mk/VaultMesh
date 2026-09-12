import { enableProdMode, provideZoneChangeDetection } from "@angular/core";
import { bootstrapApplication } from "@angular/platform-browser";
import { provideAnimations } from "@angular/platform-browser/animations";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { LocationStrategy } from "@angular/common";
import { provideRouter } from "@angular/router";
import { PopupLocationStrategy } from "../vaultmesh/popup-location";
import { VaultMeshPopupComponent, vaultMeshPopupRoutes } from "../vaultmesh/popup.component";
import { VaultMeshI18nService } from "../vaultmesh/i18n.service";

import "./scss";

// A transient remote UI: no AppModule, account SDK, migrations or popup state storage.
document.body.style.width = "400px";
document.body.style.minHeight = "540px";
document.body.style.height = "600px";
document.documentElement.classList.add("theme_light");

if (process.env.ENV === "production") {
  enableProdMode();
}

void bootstrapApplication(VaultMeshPopupComponent, {
  providers: [provideZoneChangeDetection(), provideAnimations(), provideRouter(vaultMeshPopupRoutes), { provide: LocationStrategy, useClass: PopupLocationStrategy }, { provide: I18nService, useClass: VaultMeshI18nService }],
});
