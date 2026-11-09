const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const togglePasswordButton = document.getElementById("toggle-password");
const errorText = document.getElementById("auth-error");
const submitButton = document.getElementById("auth-submit");
const totpCodeInput = document.getElementById("totp-code");

if (new URLSearchParams(location.search).has("abgelaufen")) {
    errorText.textContent = "Deine Sitzung ist abgelaufen. Bitte melde dich erneut an.";
}

togglePasswordButton.addEventListener("click", () => {
    const hidden = passwordInput.type === "password";
    if (hidden) {
        passwordInput.type = "text";
        togglePasswordButton.textContent = "Verbergen";
    } else {
        passwordInput.type = "password";
        togglePasswordButton.textContent = "Zeigen";
    }
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorText.textContent = "";
    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;

    if (!email || !password) {
        errorText.textContent = "Bitte E-Mail und Passwort eingeben.";
        return;
    }

    if (!emailInput.checkValidity() || email.length > 254) {
        errorText.textContent = "Bitte eine gültige E-Mail eingeben.";
        return;
    }

    const rawCode = totpCodeInput.value.trim();
    const totp = rawCode === "" ? null : normalizeTotpCode(rawCode);
    if (rawCode !== "" && totp === null) {
        errorText.textContent = "Der Code hat 6 Ziffern.";
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Anmelden…";

    try {

        const preloginResponse = await fetch(API_BASE + "/prelogin?email=" + encodeURIComponent(email));

        if (!preloginResponse.ok) {
            errorText.textContent = "Anmeldung gerade nicht möglich. Bitte versuche es später erneut.";
            return;
        }

        const preloginData = await preloginResponse.json();
        if (!isDefaultKdf(preloginData.kdf)) {
            errorText.textContent = "Anmeldung gerade nicht möglich. Bitte versuche es später erneut.";
            return;
        }
        const loginKey = await deriveLoginKey(password, base64ToBytes(preloginData.salt), preloginData.kdf);

        const loginResponse = await fetch(API_BASE + "/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                email: email,
                loginKey: loginKey,
                totp: totp,
            }),
        });

        if (loginResponse.status === 401) {
            totpCodeInput.value = "";
            errorText.textContent = rawCode === ""
                ? "Anmeldung fehlgeschlagen. Hast du den Code aus deiner Authenticator-App eingegeben?"
                : "Anmeldung fehlgeschlagen. Prüfe E-Mail, Passwort und Code. Jeder Code gilt nur einmal.";
            return;
        }

        if (loginResponse.status === 429) {
            const seconds = loginResponse.headers.get("Retry-After");
            errorText.textContent = `Zu viele Anmeldeversuche. Bitte versuche es in ${seconds} Sekunden erneut.`;
            return;
        }

        if (!loginResponse.ok) {
            errorText.textContent = "Anmeldung gerade nicht möglich. Bitte versuche es später erneut.";
            return;
        }

        const loginData = await loginResponse.json();
        sessionStorage.setItem("loginToken", loginData.token);
        sessionStorage.setItem("userId", loginData.userId);
        sessionStorage.setItem("email", email);
        sessionStorage.setItem("totpEnabled", String(loginData.totpEnabled));
        sessionStorage.setItem("vaultSessionId", crypto.randomUUID());
        const lastLoginKey = "lastLogin:" + loginData.userId;
        sessionStorage.setItem("previousLogin", localStorage.getItem(lastLoginKey) || "");
        localStorage.setItem(lastLoginKey, Date.now().toString());
        passwordInput.value = "";
        window.location.href = "/app/";

    } catch (error) {
        console.error(error);
        errorText.textContent = "Server nicht erreichbar. Bitte prüfe deine Internetverbindung.";
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Anmelden";
    }

});

