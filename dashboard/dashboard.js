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


function getVaultSessionId() {
    let id = sessionStorage.getItem("vaultSessionId");
    if (!id) {
        id = crypto.randomUUID();
        sessionStorage.setItem("vaultSessionId", id);
    }
    return id;
}

async function vaultRequest(method, path, body, itemId) {
    const bodyText = body ? JSON.stringify(body) : "";

    const headers = {
        "Authorization": "Bearer " + loginToken,
        // Platzhalter, solange es kein Gateway gibt 
        "X-User-Id": sessionStorage.getItem("userId"),
        "X-Session-Id": getVaultSessionId(),
    };
    if (body) {
        headers["Content-Type"] = "application/json";
    }
    if (vaultToken) {
        headers["X-Vault-Token"] = vaultToken;
    }
   
    if (itemId) {
        headers["X-Item-Id"] = itemId;
    }

    return fetch(VAULT_BASE + path, {
        method: method,
        headers: headers,
        body: body ? bodyText : undefined,
    });
}

// Fehler vom Vault lesen. Die X-Request-ID landet in der Konsole, damit findet das Backend die Logzeile sofort.
async function readVaultError(response) {
    const data = await response.json().catch(() => ({}));
    console.warn("Vault-Fehler", response.status, data.error, data.reason || "",
        "X-Request-ID:", response.headers.get("X-Request-ID"));
    return data.error;
}

function vaultErrorMessage(errorCode, fallback) {
    if (errorCode === "upstream_error") {
        return "Gerade nicht möglich. Bitte versuche es später erneut.";
    }
    if (errorCode === "integrity_error") {
        return "Achtung: Daten auf dem Server wurden verändert. Bitte melde das dem Support.";
    }
    return fallback;
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


function itemAad(itemId, part, rev) {
    const userId = sessionStorage.getItem("userId");
    return new TextEncoder().encode(`TL-L1|${userId}|${itemId}|${part}|${rev}`);
}

async function decryptPart(c1, itemId, part, rev) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: c1.slice(2, 14), additionalData: itemAad(itemId, part, rev) },
        dek,
        c1.slice(14)
    );
    const json = new TextDecoder().decode(unpad(new Uint8Array(decrypted)));
    return JSON.parse(json);
}


function pad(bytes) {
    let size = 32;
    while (size < bytes.length + 1) {
        size *= 2;
    }
    const block = new Uint8Array(size);
    block.set(bytes, 0);
    block[bytes.length] = 0x80;
    return block;
}


async function encryptPart(value, itemId, part, rev, nonce = crypto.getRandomValues(new Uint8Array(12))) {
    const block = pad(new TextEncoder().encode(JSON.stringify(value)));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: itemAad(itemId, part, rev) },
        dek,
        block
    );
    block.fill(0);

    const c1 = new Uint8Array(14 + encrypted.byteLength);
    c1.set([1, 1], 0);
    c1.set(nonce, 2);
    c1.set(new Uint8Array(encrypted), 14);
    return c1;
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
            createError.textContent = vaultErrorMessage(await readVaultError(response), "Tresor konnte nicht erstellt werden.");
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
            unlockError.textContent = vaultErrorMessage(await readVaultError(paramsResponse), "Tresor gerade nicht erreichbar.");
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
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            unlockError.textContent = errorCode === "integrity_error"
                ? "Der Tresor konnte nicht geöffnet werden."
                : vaultErrorMessage(errorCode, "Tresor konnte nicht entsperrt werden.");
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
const vaultErrorText = document.getElementById("vault-error");
const vaultTable = document.getElementById("vault-table");
const statCount = document.getElementById("stat-count");

let items = [];

const LOCKED_MESSAGE = "Der Tresor wurde gesperrt. Bitte gib dein Masterpasswort erneut ein.";

// Tresor lokal sperren (bei 401 vault_locked und später beim Sperren-Button):
// DEK und Tresor-Token verwerfen, Liste leeren, Milchglas mit "Tresor entsperren" zeigen.
function lockVault(message) {
    vaultToken = null;
    dek = null;
    items = [];
    renderItems();

    addForm.reset();
    addForm.hidden = true;
    addButton.hidden = false;
    vaultErrorText.textContent = "";

    createForm.hidden = true;
    unlockForm.hidden = false;
    unlockError.textContent = message || "";
    lock.hidden = false;
}

async function loadItems() {
    vaultErrorText.textContent = "";
    try {
        const response = await vaultRequest("GET", "/items");
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return;
            }
            vaultErrorText.textContent = vaultErrorMessage(errorCode, "Einträge konnten nicht geladen werden.");
            return;
        }
        const data = await response.json();

        items = [];
        for (const item of data.items) {
            const head = await decryptPart(base64ToBytes(item.head), item.id, "h", item.rev);
            items.push({ id: item.id, rev: item.rev, title: head.title, url: head.url, user: head.user });
        }
        renderItems();
    } catch (error) {
        console.error(error);
        vaultErrorText.textContent = error.name === "OperationError"
            ? "Ein Eintrag konnte nicht entschlüsselt werden."
            : "Tresor-Server nicht erreichbar.";
    }
}

const HIDDEN_PASSWORD = "••••••••";

function textCell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
}

function renderItems() {
    vaultList.replaceChildren();

    for (const item of items) {
        const row = document.createElement("tr");

        const passwordCell = document.createElement("td");
        const passwordText = document.createElement("span");
        passwordText.textContent = HIDDEN_PASSWORD;
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "link-button";
        toggle.textContent = "Anzeigen";
        toggle.addEventListener("click", () => toggleSecret(item, passwordText, toggle));
        passwordCell.append(passwordText, toggle);

        row.append(textCell(item.title), textCell(item.url), textCell(item.user), passwordCell);
        vaultList.append(row);
    }

    vaultTable.hidden = items.length === 0;
    vaultEmpty.hidden = items.length > 0;
    statCount.textContent = items.length;
}

// Passwort EINES Eintrags erst auf Klick holen: GET /items/secret (X-Item-Id) → C1 mit dem DEK öffnen
async function toggleSecret(item, passwordText, toggle) {
    if (toggle.textContent === "Verbergen") {
        passwordText.textContent = HIDDEN_PASSWORD;
        toggle.textContent = "Anzeigen";
        return;
    }

    toggle.disabled = true;
    vaultErrorText.textContent = "";
    try {
        const response = await vaultRequest("GET", "/items/secret", null, item.id);
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return;
            }
            vaultErrorText.textContent = errorCode === "not_found"
                ? "Diesen Eintrag gibt es nicht mehr."
                : vaultErrorMessage(errorCode, "Passwort konnte nicht geladen werden.");
            return;
        }
        const data = await response.json();
        // Für die AAD immer die rev aus der Antwort nehmen
        const secret = await decryptPart(base64ToBytes(data.data), item.id, "s", data.rev);
        passwordText.textContent = secret.pw;
        toggle.textContent = "Verbergen";
    } catch (error) {
        console.error(error);
        vaultErrorText.textContent = error.name === "OperationError"
            ? "Passwort konnte nicht entschlüsselt werden."
            : "Tresor-Server nicht erreichbar.";
    } finally {
        toggle.disabled = false;
    }
}


const addButton = document.getElementById("add-button");
const addForm = document.getElementById("add-form");
const addError = document.getElementById("add-error");

addButton.addEventListener("click", () => {
    addForm.hidden = false;
    addButton.hidden = true;
    document.getElementById("add-title").focus();
});

document.getElementById("add-cancel").addEventListener("click", () => {
    addForm.reset();
    addError.textContent = "";
    addForm.hidden = true;
    addButton.hidden = false;
});

addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addError.textContent = "";

    const title = document.getElementById("add-title").value.trim();
    const url = document.getElementById("add-url").value.trim();
    const user = document.getElementById("add-user").value.trim();
    const passwordInput = document.getElementById("add-password");

    if (!title || !passwordInput.value) {
        addError.textContent = "Bitte mindestens Titel und Passwort eingeben.";
        return;
    }

    const button = addForm.querySelector("button[type=submit]");
    button.disabled = true;

    try {
        const itemId = crypto.randomUUID();
        const rev = 1;

        const head = await encryptPart({ title: title, url: url, user: user }, itemId, "h", rev);
        const secret = await encryptPart({ pw: passwordInput.value }, itemId, "s", rev);

        const response = await vaultRequest("PUT", "/items", {
            rev: rev,
            head: bytesToBase64(head),
            secret: bytesToBase64(secret),
        }, itemId);

        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return;
            }
            addError.textContent = vaultErrorMessage(errorCode, "Eintrag konnte nicht gespeichert werden.");
            return;
        }

        items.push({ id: itemId, rev: rev, title: title, url: url, user: user });
        renderItems();

        addForm.reset();
        addForm.hidden = true;
        addButton.hidden = false;
    } catch (error) {
        console.error(error);
        addError.textContent = "Tresor-Server nicht erreichbar.";
    } finally {
        button.disabled = false;
    }
});
