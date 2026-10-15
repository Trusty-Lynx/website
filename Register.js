const form = document.getElementById("register-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const passwordConfirmInput = document.getElementById("password-confirm");
const togglePasswordButton = document.getElementById("toggle-password");
const errorText = document.getElementById("auth-error");
const submitButton = document.getElementById("auth-submit");

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
                "X-Device-Id": getDeviceId(),
            },
            body: JSON.stringify({
                email: email,
                salt: salt,
                kdf: KDF,
                loginKey: loginKey,
                device: {
                    id: getDeviceId(),
                    name: getDeviceName(),
                    publicKey: await getDevicePublicKey(),
                },
            }),
        });

        
        if (response.status === 409) {
            errorText.textContent = "Für diese E-Mail gibt es schon einen Account.";
            return;
        }

        if (!response.ok) {
            errorText.textContent = "Registrierung gerade nicht möglich. Bitte versuche es später erneut.";
            return;
        }

        const data = await response.json();
        sessionStorage.setItem("loginToken", data.token);
        sessionStorage.setItem("userId", data.userId);
        localStorage.setItem("deviceRegistered:" + email, "true");
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
