import { enableProdMode, provideZoneChangeDetection } from "@angular/core";
import { bootstrapApplication } from "@angular/platform-browser";
import { provideAnimations } from "@angular/platform-browser/animations";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshSessionComponent } from "../vaultmesh/session.component";
import { VaultMeshI18nService } from "../vaultmesh/i18n.service";

import "./scss";

// A transient remote UI: no AppModule, account SDK, migrations or popup state storage.
document.body.style.width = "400px";
document.body.style.minHeight = "540px";
document.documentElement.classList.add("theme_light");

if (process.env.ENV === "production") {
  enableProdMode();
}

void bootstrapApplication(VaultMeshSessionComponent, {
  providers: [provideZoneChangeDetection(), provideAnimations(), { provide: I18nService, useClass: VaultMeshI18nService }],
});
