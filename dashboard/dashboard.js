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

// Platzhalter-Session für den Vault (X-Session-Id), bis das Gateway sie aus dem Login-Token setzt
function getVaultSessionId() {
    let id = sessionStorage.getItem("vaultSessionId");
    if (!id) {
        id = crypto.randomUUID();
        sessionStorage.setItem("vaultSessionId", id);
    }
    return id;
}

async function vaultRequest(method, path, body) {
    const bodyText = body ? JSON.stringify(body) : "";

    const headers = {
        "Authorization": "Bearer " + loginToken,
        // Platzhalter, solange es kein Gateway gibt (Vault-Doku von Aaron)
        "X-User-Id": sessionStorage.getItem("userId"),
        "X-Session-Id": getVaultSessionId(),
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
    const keys = {
        unlockKey: await hkdf(mk, "TL-auth-v1"),
        kek: await hkdf(mk, "TL-enc-v1"),
    };
    mk.fill(0);
    return keys;
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

// Padding entfernen (ISO/IEC 7816-4): von hinten alle 00 überspringen, dann muss 80 kommen
function unpad(block) {
    let end = block.length - 1;
    while (end >= 0 && block[end] === 0x00) {
        end--;
    }
    if (block[end] !== 0x80) {
        throw new Error("Ungültiges Padding");
    }
    return block.slice(0, end);
}

// AAD für Kopf (h) oder Geheimnis (s) eines Eintrags: TL-L1|{userId}|{itemId}|{teil}|{rev}
function itemAad(itemId, part, rev) {
    const userId = sessionStorage.getItem("userId");
    return new TextEncoder().encode(`TL-L1|${userId}|${itemId}|${part}|${rev}`);
}

// C1 = 01 ‖ 01 ‖ n1 (12 B) ‖ AES-256-GCM(DEK, n1, Padding-Block, aad)
async function decryptPart(c1, itemId, part, rev) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: c1.slice(2, 14), additionalData: itemAad(itemId, part, rev) },
        dek,
        c1.slice(14)
    );
    const json = new TextDecoder().decode(unpad(new Uint8Array(decrypted)));
    return JSON.parse(json);
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
    const confirmed = document.getElementById("create-confirm").checked;

    if (password.length < 12) {
        createError.textContent = "Das Masterpasswort muss mindestens 12 Zeichen lang sein.";
        return;
    }
    if (password !== passwordConfirm) {
        createError.textContent = "Die Masterpasswörter stimmen nicht überein.";
        return;
    }
    if (!confirmed) {
        createError.textContent = "Bitte bestätige, dass ein vergessenes Masterpasswort nicht wiederherstellbar ist.";
        return;
    }

    const button = createForm.querySelector("button");
    button.disabled = true;

    try {
        const saltBytes = crypto.getRandomValues(new Uint8Array(16));
        const keys = await deriveVaultKeys(password, saltBytes, KDF);

        const dekBytes = crypto.getRandomValues(new Uint8Array(32));
        const wdek = await wrapDek(dekBytes, keys.kek);

        // securityLevel lässt der Vault im Moment noch nicht zu (400), deshalb nicht mitschicken
        const response = await vaultRequest("POST", "/vault", {
            salt: bytesToBase64(saltBytes),
            kdf: KDF,
            unlockKey: bytesToBase64(keys.unlockKey),
            wdek: bytesToBase64(wdek),
        });
        keys.unlockKey.fill(0);
        keys.kek.fill(0);

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
        dekBytes.fill(0);
        lock.hidden = true;
        await loadItems();
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
        if (paramsResponse.status === 404) {
            unlockForm.hidden = true;
            createForm.hidden = false;
            return;
        }
        if (!paramsResponse.ok) {
            unlockError.textContent = "Tresor gerade nicht erreichbar.";
            return;
        }
        const params = await paramsResponse.json();
        if (!isDefaultKdf(params.kdf)) {
            unlockError.textContent = "Der Tresor konnte nicht geöffnet werden.";
            return;
        }

        const keys = await deriveVaultKeys(passwordInput.value, base64ToBytes(params.salt), params.kdf);

        const response = await vaultRequest("POST", "/vault/unlock", {
            unlockKey: bytesToBase64(keys.unlockKey),
        });
        keys.unlockKey.fill(0);

        if (response.status === 401) {
            unlockError.textContent = "Masterpasswort ist falsch.";
            return;
        }
        if (response.status === 429) {
            const seconds = response.headers.get("Retry-After");
            unlockError.textContent = `Zu viele Fehlversuche. Bitte ${seconds} Sekunden warten.`;
            return;
        }
        if (response.status === 500) {
            unlockError.textContent = "Der Tresor konnte nicht geöffnet werden.";
            return;
        }
        if (!response.ok) {
            unlockError.textContent = "Tresor konnte nicht entsperrt werden.";
            return;
        }

        const data = await response.json();
        const wdek = base64ToBytes(data.wdek);
        if (wdek.length !== 62 || wdek[0] !== 1 || wdek[1] !== 1) {
            unlockError.textContent = "Der Tresor konnte nicht geöffnet werden.";
            return;
        }
        const dekBytes = await unwrapDek(wdek, keys.kek);
        keys.kek.fill(0);

        vaultToken = data.vaultToken;
        dek = await crypto.subtle.importKey("raw", dekBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
        dekBytes.fill(0);
        passwordInput.value = "";
        lock.hidden = true;
        await loadItems();
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


const vaultList = document.getElementById("vault-list");
const vaultEmpty = document.getElementById("vault-empty");
const statCount = document.getElementById("stat-count");

let items = [];

async function loadItems() {
    const response = await vaultRequest("GET", "/items");
    if (!response.ok) {
        throw new Error("Einträge konnten nicht geladen werden: " + response.status);
    }
    const data = await response.json();

    items = [];
    for (const item of data.items) {
        const head = await decryptPart(base64ToBytes(item.head), item.id, "h", item.rev);
        items.push({ id: item.id, rev: item.rev, title: head.title, url: head.url, user: head.user });
    }
    renderItems();
}

function renderItems() {
    vaultList.replaceChildren();

    for (const item of items) {
        const li = document.createElement("li");
        li.className = "vault-item";

        const title = document.createElement("strong");
        title.textContent = item.title;
        const user = document.createElement("span");
        user.textContent = item.user;
        const url = document.createElement("span");
        url.textContent = item.url;

        li.append(title, user, url);
        vaultList.append(li);
    }

    vaultEmpty.hidden = items.length > 0;
    statCount.textContent = items.length;
}
