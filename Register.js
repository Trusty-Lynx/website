const form = document.getElementById("register-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const passwordConfirmInput = document.getElementById("password-confirm");
const togglePasswordButton = document.getElementById("toggle-password");
const errorText = document.getElementById("auth-error");
const submitButton = document.getElementById("auth-submit");
const totpSection = document.getElementById("totp-setup");
const totpQr = document.getElementById("totp-qr");
const totpSecretText = document.getElementById("totp-secret");
const totpCodeInput = document.getElementById("totp-code");

// Ein Secret pro Einrichtung. Nur im Speicher, nie in localStorage/sessionStorage
let totpSecret = null;
let totpEmail = null;

togglePasswordButton.addEventListener("click", () => {
    const hidden = passwordInput.type === "password";
    if (hidden) {
        passwordInput.type = "text";
        passwordConfirmInput.type = "text";
        togglePasswordButton.textContent = "Verbergen";
    } else {
        passwordInput.type = "password";
        passwordConfirmInput.type = "password";
        togglePasswordButton.textContent = "Zeigen";
    }
});


form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorText.textContent = "";

    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;
    const passwordConfirm = passwordConfirmInput.value;

    if (!email || !password || !passwordConfirm) {
        errorText.textContent = "Bitte alle Felder ausfüllen.";
        return;
    }

    if (!emailInput.checkValidity() || email.length > 254) {
        errorText.textContent = "Bitte eine gültige E-Mail eingeben.";
        return;
    }

    if (password.length < 12) {
        errorText.textContent = "Das Passwort muss mindestens 12 Zeichen lang sein.";
        return;
    }

    if (password !== passwordConfirm) {
        errorText.textContent = "Die Passwörter stimmen nicht überein.";
        return;
    }

    // Erster Klick: nur QR-Code zeigen, noch kein Request. Neue E-Mail: neues Secret, weil die E-Mail im Eintrag der App steht
    if (totpSecret === null || totpEmail !== email) {
        if (totpSecret !== null) {
            totpSecret.fill(0);
            errorText.textContent = "Die E-Mail hat sich geändert. Bitte scanne den neuen QR-Code.";
        }
        totpSecret = newTotpSecret();
        totpEmail = email;
        showTotpSetup(totpQr, totpSecretText, email, totpSecret);
        totpSection.hidden = false;
        totpCodeInput.value = "";
        totpCodeInput.focus();
        return;
    }

    const code = normalizeTotpCode(totpCodeInput.value);
    if (code === null) {
        errorText.textContent = "Bitte den 6-stelligen Code aus deiner Authenticator-App eingeben.";
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Wird erstellt…";

    try {
        const saltBytes = crypto.getRandomValues(new Uint8Array(16));
        const salt = bytesToBase64(saltBytes);

        const loginKey = await deriveLoginKey(password, saltBytes, KDF);
        
        const response = await fetch(API_BASE + "/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                email: email,
                salt: salt,
                kdf: KDF,
                loginKey: loginKey,
                totp: { secret: bytesToBase64(totpSecret), code: code },
            }),
        });

        // Falscher Code: dasselbe Secret behalten, der Nutzer hat es ja schon in der App
        if (response.status === 400) {
            const error = await response.json().catch(() => ({}));
            if (error.reason === "invalid_totp") {
                totpCodeInput.value = "";
                totpCodeInput.focus();
                errorText.textContent = "Der Code stimmt nicht. Warte auf den nächsten Code in der App und gib ihn ein.";
                return;
            }
        }

        if (response.status === 409) {
            errorText.textContent = "Für diese E-Mail gibt es schon einen Account.";
            return;
        }

        if (!response.ok) {
            errorText.textContent = "Registrierung gerade nicht möglich. Bitte versuche es später erneut.";
            return;
        }

        const data = await response.json();
        totpSecret.fill(0);
        totpSecret = null;
        sessionStorage.setItem("loginToken", data.token);
        sessionStorage.setItem("userId", data.userId);
        sessionStorage.setItem("email", email);
        sessionStorage.setItem("totpEnabled", "true");
        // Neue Platzhalter-Session für den Vault: ein neuer Login macht den alten Tresor-Token ungültig
        sessionStorage.setItem("vaultSessionId", crypto.randomUUID());
        // Erster Login: es gibt noch keinen vorherigen, den jetzigen fürs nächste Mal speichern
        sessionStorage.setItem("previousLogin", "");
        localStorage.setItem("lastLogin:" + data.userId, Date.now().toString());
        passwordInput.value = "";
        passwordConfirmInput.value = "";
        window.location.href = "Dashboard.html";


    } catch (error) {
        console.error(error);
        errorText.textContent = "Server nicht erreichbar. Bitte prüfe deine Internetverbindung.";
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Account erstellen";
    }


});
