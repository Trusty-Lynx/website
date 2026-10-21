

const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const togglePasswordButton = document.getElementById("toggle-password");
const errorText = document.getElementById("auth-error");
const submitButton = document.getElementById("auth-submit");

// Vom Dashboard hierher geschickt, weil der Login abgelaufen ist
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
            }),
        });

        if (loginResponse.status === 401) {
            errorText.textContent = "Anmeldung fehlgeschlagen.";
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
        // Neue Platzhalter-Session für den Vault: ein neuer Login macht den alten Tresor-Token ungültig
        sessionStorage.setItem("vaultSessionId", crypto.randomUUID());
        passwordInput.value = "";
        window.location.href = "Dashboard.html";

    } catch (error) {
        console.error(error);
        errorText.textContent = "Server nicht erreichbar. Bitte prüfe deine Internetverbindung.";
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Anmelden";
    }

});

