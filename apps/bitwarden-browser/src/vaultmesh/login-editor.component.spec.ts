import { TestBed } from "@angular/core/testing";
import { NgModel } from "@angular/forms";
import { By } from "@angular/platform-browser";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshLoginEditorComponent } from "./login-editor.component";
import { LoginDraft } from "./login-draft";

describe("CT-ITEM-001 Bitwarden edit form", () => {
  it("uses password controls for secret values and requires a password for creation", async () => {
    await TestBed.configureTestingModule({
      imports: [VaultMeshLoginEditorComponent],
      providers: [{ provide: I18nService, useValue: { t: (key: string) => key } }],
    }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshLoginEditorComponent);
    const draft = new LoginDraft();
    draft.addField();
    fixture.componentRef.setInput("draft", draft);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    const element = fixture.nativeElement as HTMLElement;
    // Dynamic [name] is consumed by NgModel rather than written as a DOM attribute.
    const inputFor = (name: string): HTMLInputElement => fixture.debugElement.queryAll(By.directive(NgModel))
      .find((control) => control.injector.get(NgModel).name === name)!.nativeElement;
    for (const name of ["password", "totp", "field-value-0"]) {
      expect(inputFor(name).type).toBe("password");
    }
    expect(element.querySelector('button[type="submit"]')!.getAttribute("aria-disabled")).toBe("true");
    const save = jest.fn();
    fixture.componentInstance.save.subscribe(save);
    element.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    expect(save).not.toHaveBeenCalled();
    const setInput = (name: string, value: string) => {
      const input = inputFor(name);
      input.value = value;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    };
    setInput("title", "New login");
    setInput("password", "synthetic-password");
    setInput("field-name-0", "key");
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(element.querySelector('button[type="submit"]')!.getAttribute("aria-disabled")).not.toBe("true");
    element.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    expect(save).toHaveBeenCalledTimes(1);
    expect(draft.toInput().password).toBe("synthetic-password");
    draft.clear();
    fixture.destroy();
  });
});
