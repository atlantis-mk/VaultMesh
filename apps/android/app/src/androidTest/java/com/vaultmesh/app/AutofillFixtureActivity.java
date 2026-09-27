package com.vaultmesh.app;

import android.app.Activity;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import android.widget.Button;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Standalone activity in the test APK: it cannot load the target APK's Kotlin runtime. */
public class AutofillFixtureActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 100, 32, 32);
        TextView heading = new TextView(this);
        heading.setText("VaultMesh Autofill Test " + getIntent().getStringExtra("nonce"));
        layout.addView(heading);
        String mode = getIntent().getStringExtra("mode");
        if (mode != null && mode.startsWith("otp")) {
            addOtpFixture(layout, mode);
            setContentView(layout);
            return;
        }
        EditText username = "unlabeled".equals(mode) ? unlabeledUsername() :
            field(1001, "TEST_USERNAME", View.AUTOFILL_HINT_USERNAME,
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        EditText password = field(1002, "TEST_PASSWORD", View.AUTOFILL_HINT_PASSWORD,
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        if ("register".equals(mode)) password.setAutofillHints("newPassword");
        boolean change = "change".equals(mode);
        boolean multi = "multi".equals(mode);
        if (multi) password.setVisibility(View.GONE);
        layout.addView(username);
        layout.addView(password);
        EditText newPassword = field(1004, "TEST_NEW_PASSWORD", "newPassword", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText confirmation = field(1005, "TEST_CONFIRM_PASSWORD", "newPassword", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        if (change) { layout.addView(newPassword); layout.addView(confirmation); }

        TextView status = new TextView(this);
        status.setText("TEST_EMPTY");
        layout.addView(status);
        TextWatcher watcher = new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (username.getText().toString().equals("synthetic-user") && password.getText().toString().equals("synthetic-login-password")) status.setText("TEST_FILL_OK");
                else if (username.getText().toString().equals("synthetic-user") && password.getText().toString().equals("other-login-password")) status.setText("TEST_USERNAME_PRESERVED");
                else if (username.length() == 0 && password.length() == 0) status.setText("TEST_EMPTY");
                else status.setText("TEST_PARTIAL_FILL");
            }
            public void afterTextChanged(Editable s) {}
        };
        username.addTextChangedListener(watcher);
        password.addTextChangedListener(watcher);
        button(layout, "TEST_REQUEST_FILL", () -> {
            EditText focused = username.getVisibility() == View.VISIBLE ? username : password;
            focused.requestFocus();
            getSystemService(AutofillManager.class).requestAutofill(focused);
        });
        button(layout, "TEST_REQUEST_PASSWORD_FILL", () -> {
            password.requestFocus();
            getSystemService(AutofillManager.class).requestAutofill(password);
        });
        button(layout, "TEST_CLEAR_PASSWORD", () -> password.setText(""));
        button(layout, "TEST_ENTER_SYNTHETIC", () -> {
            if (username.getVisibility() == View.VISIBLE) username.setText("synthetic-user");
            if (password.getVisibility() == View.VISIBLE) password.setText("synthetic-login-password");
            if (change) { newPassword.setText("synthetic-updated-password"); confirmation.setText("synthetic-updated-password"); }
        });
        if (multi) button(layout, "TEST_NEXT", () -> {
            username.setVisibility(View.GONE);
            password.setVisibility(View.VISIBLE);
            password.requestFocus();
            getSystemService(AutofillManager.class).requestAutofill(password);
        });
        button(layout, "TEST_SUBMIT", () -> getSystemService(AutofillManager.class).commit());
        setContentView(layout);
    }
    private void addOtpFixture(LinearLayout layout, String mode) {
        TextView status = new TextView(this);
        status.setText("TEST_OTP_EMPTY");
        layout.addView(status);
        if ("otp-split".equals(mode)) {
            EditText[] digits = new EditText[6];
            for (int i = 0; i < digits.length; i++) {
                digits[i] = field(2000 + i, "TEST_OTP_DIGIT_" + (i + 1), "smsOTPCode" + (i + 1), InputType.TYPE_CLASS_NUMBER);
                digits[i].addTextChangedListener(new TextWatcher() {
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                        boolean filled = true;
                        for (EditText digit : digits) filled &= digit.length() == 1;
                        status.setText(filled ? "TEST_OTP_FILLED" : "TEST_OTP_EMPTY");
                    }
                    public void afterTextChanged(Editable s) {}
                });
                layout.addView(digits[i]);
            }
            button(layout, "TEST_REQUEST_OTP", () -> {
                digits[0].requestFocus();
                getSystemService(AutofillManager.class).requestAutofill(digits[0]);
            });
        } else {
            String hint = "otp-numeric".equals(mode) ? null :
                "otp-app".equals(mode) ? "2faAppOTPCode" :
                "otp-email".equals(mode) ? "emailOTPCode" : "smsOTPCode";
            EditText otp = field(2001, "otp-numeric".equals(mode) ? "TEST_NUMERIC" : "TEST_OTP", hint, InputType.TYPE_CLASS_NUMBER);
            otp.addTextChangedListener(new TextWatcher() {
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    status.setText(s.length() > 0 ? "TEST_OTP_FILLED" : "TEST_OTP_EMPTY");
                }
                public void afterTextChanged(Editable s) {}
            });
            layout.addView(otp);
            button(layout, "TEST_REQUEST_OTP", () -> {
                otp.requestFocus();
                getSystemService(AutofillManager.class).requestAutofill(otp);
            });
        }
    }
    private EditText field(int id, String label, String hint, int type) {
        EditText field = new EditText(this);
        field.setId(id);
        field.setHint(label);
        field.setContentDescription(label);
        if (hint != null) field.setAutofillHints(hint);
        field.setInputType(type);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_YES);
        field.setShowSoftInputOnFocus(false);
        return field;
    }
    private EditText unlabeledUsername() {
        AutoCompleteTextView field = new AutoCompleteTextView(this);
        field.setContentDescription("TEST_USERNAME");
        field.setInputType(InputType.TYPE_CLASS_TEXT);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_YES);
        field.setShowSoftInputOnFocus(false);
        return field;
    }
    private void button(LinearLayout layout, String text, Runnable action) {
        Button button = new Button(this);
        button.setText(text);
        button.setOnClickListener(v -> action.run());
        layout.addView(button);
    }
}
