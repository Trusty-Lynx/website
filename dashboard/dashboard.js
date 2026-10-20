const logoutButton = document.getElementById("logout-button");

const loginToken = sessionStorage.getItem("loginToken");

// Tresor-Token und Tresorschlüssel nur im Arbeitsspeicher, nie im Storage
let vaultToken = null;
let dek = null;

if (!loginToken) {
    window.location.href = "Login.html";
}

logoutButton.addEventListener("click", async () => {
    logoutButton.disabled = true;

    try {
        await fetch(API_BASE + "/logout", {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + loginToken,
                "X-Device-Id": await getDeviceId(),
            },
        });
    } catch (error) {
        console.error(error);
    }

    sessionStorage.clear();
    window.location.href = "Login.html";
});


const lockMessage = document.getElementById("lock-message");
const unlockForm = document.getElementById("unlock-form");
const createForm = document.getElementById("create-form");

async function vaultRequest(method, path, body) {
    const bodyText = body ? JSON.stringify(body) : "";

    const headers = {
        "Authorization": "Bearer " + loginToken,
        ...(await signRequest(method, path, bodyText)),
    };
    if (body) {
        headers["Content-Type"] = "application/json";
    }
    if (vaultToken) {
        headers["X-Vault-Token"] = vaultToken;
    }

    return fetch(VAULT_BASE + path, {
        method: method,
        headers: headers,
        body: body ? bodyText : undefined,
    });
}

async function deriveVaultKeys(password, saltBytes, kdf) {
    const mk = await hashwasm.argon2id({
        password: password,
        salt: saltBytes,
        parallelism: kdf.p,
        iterations: kdf.t,
        memorySize: kdf.m,
        hashLength: kdf.len,
        outputType: "binary",
    });
    return {
        unlockKey: await hkdf(mk, "TL-auth-v1"),
        kek: await hkdf(mk, "TL-enc-v1"),
    };
}


async function wrapDek(dekBytes, kekBytes) {
    const kek = await crypto.subtle.importKey("raw", kekBytes, "AES-GCM", false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: nonce,
            additionalData: new TextEncoder().encode("TL-DEK|" + sessionStorage.getItem("userId")),
        },
        kek,
        dekBytes
    );

    const wdek = new Uint8Array(62);
    wdek.set([1, 1], 0);
    wdek.set(nonce, 2);
    wdek.set(new Uint8Array(encrypted), 14);
    return wdek;
}

async function unwrapDek(wdek, kekBytes) {
    const kek = await crypto.subtle.importKey("raw", kekBytes, "AES-GCM", false, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: wdek.slice(2, 14),
            additionalData: new TextEncoder().encode("TL-DEK|" + sessionStorage.getItem("userId")),
        },
        kek,
        wdek.slice(14)
    );
    return new Uint8Array(decrypted);
}

async function showLock() {
    try {
        const response = await vaultRequest("GET", "/vault/params");

        if (response.status === 404) {
            createForm.hidden = false;
        } else if (response.ok) {
            unlockForm.hidden = false;
        } else {
            lockMessage.textContent = "Tresor gerade nicht erreichbar. Bitte lade die Seite neu.";
        }
    } catch (error) {
        console.error(error);
        lockMessage.textContent = "Tresor-Server nicht erreichbar.";
    }
}

showLock();


const lock = document.getElementById("lock");
const createError = document.getElementById("create-error");

createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    createError.textContent = "";

    const password = document.getElementById("create-password").value;
    const passwordConfirm = document.getElementById("create-password-confirm").value;
    const securityLevel = document.getElementById("create-level").value;

    if (password.length < 12) {
        createError.textContent = "Das Masterpasswort muss mindestens 12 Zeichen lang sein.";
        return;
    }
    if (password !== passwordConfirm) {
        createError.textContent = "Die Masterpasswörter stimmen nicht überein.";
        return;
    }

    const button = createForm.querySelector("button");
    button.disabled = true;

    try {
        const saltBytes = crypto.getRandomValues(new Uint8Array(16));
        const keys = await deriveVaultKeys(password, saltBytes, KDF);

        const dekBytes = crypto.getRandomValues(new Uint8Array(32));
        const wdek = await wrapDek(dekBytes, keys.kek);

        const response = await vaultRequest("POST", "/vault", {
            securityLevel: securityLevel,
            salt: bytesToBase64(saltBytes),
            kdf: KDF,
            unlockKey: bytesToBase64(keys.unlockKey),
            wdek: bytesToBase64(wdek),
        });

        if (response.status === 409) {
            createForm.hidden = true;
            unlockForm.hidden = false;
            return;
        }
        if (!response.ok) {
            createError.textContent = "Tresor konnte nicht erstellt werden.";
            return;
        }

        const data = await response.json();
        vaultToken = data.vaultToken;
        dek = await crypto.subtle.importKey("raw", dekBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
        lock.hidden = true;
    } catch (error) {
        console.error(error);
        createError.textContent = "Tresor-Server nicht erreichbar.";
    } finally {
        button.disabled = false;
    }
});

const unlockError = document.getElementById("unlock-error");

unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    unlockError.textContent = "";

    const passwordInput = document.getElementById("unlock-password");
    if (!passwordInput.value) {
        unlockError.textContent = "Bitte Masterpasswort eingeben.";
        return;
    }

    const button = unlockForm.querySelector("button");
    button.disabled = true;

    try {
        const paramsResponse = await vaultRequest("GET", "/vault/params");
        if (!paramsResponse.ok) {
            unlockError.textContent = "Tresor gerade nicht erreichbar.";
            return;
        }
        const params = await paramsResponse.json();

        const keys = await deriveVaultKeys(passwordInput.value, base64ToBytes(params.salt), params.kdf);

        const response = await vaultRequest("POST", "/vault/unlock", {
            unlockKey:bytesToBase64(keys.unlockKey),
        });

        if (response.status === 401) {
            unlockError.textContent = "Masterpasswort ist falsch.";
            return;
        }
        if (response.status === 429) {
            const seconds = response.headers.get("Retry-After");
            unlockError.textContent = `Zu viele Fehlversuche. Bitte ${seconds} Sekunden warten.`;
            return;
        }
        if (!response.ok) {
            unlockError.textContent = "Tresor konnte nicht entsperrt werden.";
            return;
        }

        const data = await response.json();
        const dekBytes = await unwrapDek(base64ToBytes(data.wdek), keys.kek);

        vaultToken = data.vaultToken;
        dek = await crypto.subtle.importKey("raw", dekBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
        passwordInput.value = "";
        lock.hidden = true;
    } catch (error) {
        console.error(error);
        if (error.name === "OperationError") {
            unlockError.textContent = "Tresor konnte nicht geöffnet werden.";
        } else {
            unlockError.textContent = "Tresor-Server nicht erreichbar.";
        }
    } finally {
        button.disabled = false;
    }
});