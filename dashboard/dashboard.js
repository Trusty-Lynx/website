const logoutButton = document.getElementById("logout-button");

const loginToken = sessionStorage.getItem("loginToken");

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

let vaultToken = null;
let dek = null;

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

