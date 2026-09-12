import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ButtonModule, FormFieldModule, CheckboxModule } from "@bitwarden/components";
import { LoginDraft } from "./login-draft";

@Component({
  selector: "vaultmesh-login-editor",
  templateUrl: "./login-editor.component.html",
  imports: [FormsModule, ButtonModule, FormFieldModule, CheckboxModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class VaultMeshLoginEditorComponent {
  @Input({ required: true }) draft!: LoginDraft;
  @Input() canImportFile = false;
  @Input() canScanQr = false;
  @Output() scanQr = new EventEmitter<void>();
  @Output() importFile = new EventEmitter<void>();
  @Output() save = new EventEmitter<void>();
  @Output() cancel = new EventEmitter<void>();
  @Output() remove = new EventEmitter<void>();
}
