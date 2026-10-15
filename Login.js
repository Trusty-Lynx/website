const API_BASE = "/api";

const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const togglePasswordButton = document.getElementById("toggle-password");
const errorText = document.getElementById("auth-error");
const submitButton = document.getElementById("auth-submit");

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
        const salt = preloginData.salt;

        const kdf = preloginData.kdf;
        const loginKeyBytes = await hashwasm.argon2id({
            password: password,
            salt: base64ToBytes(salt),
            parallelism: kdf.p,
            iterations: kdf.t,
            memorySize: kdf.m,
            hashLength: kdf.len,
            outputType: "binary",
        });

        const loginKey = bytesToBase64(loginKeyBytes);

        const loginBody = { email: email, loginKey: loginKey };

        const firstLogin = localStorage.getItem("deviceRegistered:" + email) !== "true";
        if (firstLogin) {
            loginBody.device = {
                name: getDeviceName(),
                publicKey: await getDevicePublicKey(),
            };
        }

        const loginResponse = await fetch(API_BASE + "/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Device-Id": getDeviceId(),
            },
            body: JSON.stringify(loginBody),
        });

        if (loginResponse.status === 401) {
            errorText.textContent = "E-Mail oder Passwort ist falsch.";
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
        passwordInput.value = "";
        localStorage.setItem("deviceRegistered:" + email, "true");
        window.location.href = "Dashboard.html";

    } catch (error) {
        console.error(error); 
        errorText.textContent = "Server nicht erreichbar. Bitte prüfe deine Internetverbindung.";
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Anmelden";
    }

});

function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function getDeviceId() {
    let id = localStorage.getItem("deviceId");
    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem("deviceId", id);
    }
    return id;
}

function getDeviceName() {
    const platform = navigator.userAgentData?.platform || navigator.platform || "Unknown";
    return ("Browser auf " + platform).slice(0, 100);
}


async function getDevicePublicKey() {
    let keyPair = await loadDeviceKeyPair();
    if (!keyPair) {
        const generated = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign", "verify"]
        );
        keyPair = { publicKey: generated.publicKey, privateKey: generated.privateKey };
        await saveDeviceKeyPair(keyPair);
    }
    const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    return bytesToBase64(new Uint8Array(raw));
}

function openKeyStore() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("trusty-lynx", 1);
        request.onupgradeneeded = () => request.result.createObjectStore("keys");
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function loadDeviceKeyPair() {
    const db = await openKeyStore();
    return new Promise((resolve, reject) => {
        const request = db.transaction("keys").objectStore("keys").get("device");
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function saveDeviceKeyPair(keyPair) {
    const db = await openKeyStore();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction("keys", "readwrite");
        transaction.objectStore("keys").put(keyPair, "device");
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
    });
}


