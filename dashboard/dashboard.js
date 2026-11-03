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


function goToLogin() {
    sessionStorage.clear();
    window.location.href = "Login.html?abgelaufen";
}


async function readVaultError(response) {
    const data = await response.json().catch(() => ({}));
    console.warn("Vault-Fehler", response.status, data.error, data.reason || "",
        "X-Request-ID:", response.headers.get("X-Request-ID"));
    if (response.status === 401 && data.error === "unauthorized") {
        goToLogin();
    }
    return data.error;
}

function vaultErrorMessage(errorCode, fallback) {
    // Einer der beiden Crypto-Services (AES / ChaCha) ist weg, der Vault sagt in reason welcher
    if (errorCode === "crypto_unavailable") {
        return "Verschlüsselungsservice ist gerade nicht erreichbar. Versuche es mit einem anderen oder später wieder.";
    }
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
            lockMessage.textContent = vaultErrorMessage(await readVaultError(response),
                "Tresor gerade nicht erreichbar. Bitte lade die Seite neu.");
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
        resetAutoLock();
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
        resetAutoLock();
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


function showLastLogin() {
    const previous = sessionStorage.getItem("previousLogin");
    document.getElementById("stat-last-login").textContent = previous
        ? new Date(Number(previous)).toLocaleString("de-DE", {
            day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
        }) + " Uhr"
        : "Erster Login";
}

showLastLogin();

let items = [];

const LOCKED_MESSAGE = "Der Tresor wurde gesperrt. Bitte gib dein Masterpasswort erneut ein.";


function lockVault(message) {
    clearTimeout(autoLockTimer);
    vaultToken = null;
    dek = null;
    items = [];
    renderItems();

    closeItemForm();
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
            // alg: welcher Crypto-Service den Eintrag auf dem Server verschlüsselt (älterer Vault ohne Feld → chacha)
            items.push({ id: item.id, rev: item.rev, title: head.title, url: head.url, user: head.user, alg: item.alg || "chacha" });
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


const COPY_ICON = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"
    stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <rect x="8.5" y="3.5" width="10" height="13" rx="2.2"/>
    <path d="M6.6 8.3C6.2 8.7 6 9.1 6 9.6V19.5C6 20.3 6.7 21 7.5 21H14.2C15 21 15.7 20.3 15.7 19.5V18.6"/>
</svg>`;
const CHECK_ICON = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"
    stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M5 12.5L10 17.5L19 7"/>
</svg>`;

function textCell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
}

function renderItems() {
    vaultList.replaceChildren();

    for (const item of items) {
        const row = document.createElement("tr");

        // Passwort: Punkte, daneben das Kopier-Symbol, rechts "Anzeigen"
        const passwordCell = document.createElement("td");
        const passwordText = document.createElement("span");
        passwordText.textContent = HIDDEN_PASSWORD;

        const copy = document.createElement("button");
        copy.type = "button";
        copy.className = "icon-button";
        copy.innerHTML = COPY_ICON;
        copy.title = "Passwort kopieren";
        copy.setAttribute("aria-label", "Passwort kopieren");
        copy.addEventListener("click", () => copySecret(item, copy));

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "link-button";
        toggle.textContent = "Anzeigen";
        toggle.addEventListener("click", () => toggleSecret(item, passwordText, toggle));

        passwordCell.append(passwordText, copy, toggle);

        const editCell = document.createElement("td");
        const edit = document.createElement("button");
        edit.type = "button";
        edit.className = "link-button";
        edit.textContent = "Bearbeiten";
        edit.addEventListener("click", () => openItemForm(item));
        editCell.append(edit);

        row.append(textCell(item.title), textCell(item.url), textCell(item.user), passwordCell, editCell);
        vaultList.append(row);
    }

    vaultTable.hidden = items.length === 0;
    vaultEmpty.hidden = items.length > 0;
    statCount.textContent = items.length;
}


async function fetchSecret(item) {
    vaultErrorText.textContent = "";
    try {
        const response = await vaultRequest("GET", "/items/secret", null, item.id);
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return null;
            }
            vaultErrorText.textContent = errorCode === "not_found"
                ? "Diesen Eintrag gibt es nicht mehr."
                : vaultErrorMessage(errorCode, "Passwort konnte nicht geladen werden.");
            return null;
        }
        const data = await response.json();
        const secret = await decryptPart(base64ToBytes(data.data), item.id, "s", data.rev);
        return secret.pw;
    } catch (error) {
        console.error(error);
        vaultErrorText.textContent = error.name === "OperationError"
            ? "Passwort konnte nicht entschlüsselt werden."
            : "Tresor-Server nicht erreichbar.";
        return null;
    }
}

async function toggleSecret(item, passwordText, toggle) {
    if (toggle.textContent === "Verbergen") {
        passwordText.textContent = HIDDEN_PASSWORD;
        toggle.textContent = "Anzeigen";
        return;
    }

    toggle.disabled = true;
    const password = await fetchSecret(item);
    toggle.disabled = false;
    if (password !== null) {
        passwordText.textContent = password;
        toggle.textContent = "Verbergen";
    }
}

// Passwort in die Zwischenablage, nach 30 s wieder löschen
async function copySecret(item, copy) {
    copy.disabled = true;
    const password = await fetchSecret(item);
    copy.disabled = false;
    if (password === null) {
        return;
    }

    try {
        await navigator.clipboard.writeText(password);
        copy.innerHTML = CHECK_ICON;
        setTimeout(() => {
            copy.innerHTML = COPY_ICON;
        }, 1500);
        setTimeout(() => {
            navigator.clipboard.writeText("").catch(() => {});
        }, 30000);
    } catch (error) {
        console.error(error);
        vaultErrorText.textContent = "Kopieren nicht möglich.";
    }
}


// ---------- Formular: Passwort hinzufügen bzw. Eintrag bearbeiten ----------

const addButton = document.getElementById("add-button");
const addForm = document.getElementById("add-form");
const addFormTitle = document.getElementById("add-form-title");
const addError = document.getElementById("add-error");
const deleteButton = document.getElementById("add-delete");
const titleInput = document.getElementById("add-title");
const urlInput = document.getElementById("add-url");
const userInput = document.getElementById("add-user");
const passwordInput = document.getElementById("add-password");
const algInput = document.getElementById("add-alg");

// null = neuer Eintrag, sonst der Eintrag, der gerade bearbeitet wird
let editingItem = null;

async function openItemForm(item) {
    addForm.reset();
    addError.textContent = "";
    editingItem = item || null;

    addFormTitle.textContent = item ? "Eintrag bearbeiten" : "Passwort hinzufügen";
    deleteButton.hidden = !item;
    addForm.hidden = false;
    addButton.hidden = true;
    // Während das Formular offen ist, nur das Formular zeigen, nicht die Tabelle darunter
    vaultTable.hidden = true;
    vaultEmpty.hidden = true;

    if (item) {
        titleInput.value = item.title;
        urlInput.value = item.url;
        userInput.value = item.user;
        algInput.value = item.alg;
        // Das Passwort kommt nur auf diesen Klick vom Vault, wie bei "Anzeigen"
        const password = await fetchSecret(item);
        if (password === null) {
            closeItemForm();
            return;
        }
        passwordInput.value = password;
    }
    titleInput.focus();
}

function closeItemForm() {
    addForm.reset();
    addError.textContent = "";
    addForm.hidden = true;
    addButton.hidden = false;
    deleteButton.hidden = true;
    editingItem = null;
    vaultTable.hidden = items.length === 0;
    vaultEmpty.hidden = items.length > 0;
}

addButton.addEventListener("click", () => openItemForm(null));

document.getElementById("add-cancel").addEventListener("click", closeItemForm);

addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addError.textContent = "";

    const title = titleInput.value.trim();
    const url = urlInput.value.trim();
    const user = userInput.value.trim();

    if (!title || !passwordInput.value) {
        addError.textContent = "Bitte mindestens Titel und Passwort eingeben.";
        return;
    }

    const button = addForm.querySelector("button[type=submit]");
    button.disabled = true;

    try {
        
        const itemId = editingItem ? editingItem.id : crypto.randomUUID();
        const rev = editingItem ? editingItem.rev + 1 : 1;

        const head = await encryptPart({ title: title, url: url, user: user }, itemId, "h", rev);
        const secret = await encryptPart({ pw: passwordInput.value }, itemId, "s", rev);

        const response = await vaultRequest("PUT", "/items", {
            rev: rev,
            head: bytesToBase64(head),
            secret: bytesToBase64(secret),
            // Welcher Crypto-Service Schicht 2 macht. Wechsel beim Bearbeiten: der Vault verschlüsselt einfach neu.
            alg: algInput.value,
        }, itemId);

        if (response.status === 409) {
            
            closeItemForm();
            await loadItems();
            vaultErrorText.textContent = "Der Eintrag wurde inzwischen woanders geändert. Bitte prüfe ihn und bearbeite ihn erneut.";
            return;
        }
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return;
            }
            addError.textContent = vaultErrorMessage(errorCode, "Eintrag konnte nicht gespeichert werden.");
            return;
        }

        const saved = { id: itemId, rev: rev, title: title, url: url, user: user, alg: algInput.value };
        if (editingItem) {
            items = items.map((other) => (other.id === itemId ? saved : other));
        } else {
            items.push(saved);
        }
        renderItems();
        closeItemForm();
    } catch (error) {
        console.error(error);
        addError.textContent = "Tresor-Server nicht erreichbar.";
    } finally {
        button.disabled = false;
    }
});

// Eigenes Fenster statt confirm(): liefert true bei "Löschen", false bei "Abbrechen" oder Esc
const deleteDialog = document.getElementById("delete-dialog");

function confirmDelete() {
    return new Promise((resolve) => {
        document.getElementById("delete-confirm").onclick = () => {
            deleteDialog.close();
            resolve(true);
        };
        document.getElementById("delete-cancel").onclick = () => {
            deleteDialog.close();
            resolve(false);
        };
        deleteDialog.oncancel = () => resolve(false);
        deleteDialog.showModal();
    });
}

deleteButton.addEventListener("click", async () => {
    if (!editingItem) {
        return;
    }
    if (!(await confirmDelete())) {
        return;
    }

    deleteButton.disabled = true;
    try {
        const itemId = editingItem.id;
        const response = await vaultRequest("DELETE", "/items", null, itemId);

        if (!response.ok && response.status !== 404) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") {
                lockVault(LOCKED_MESSAGE);
                return;
            }
            addError.textContent = vaultErrorMessage(errorCode, "Eintrag konnte nicht gelöscht werden.");
            return;
        }

        
        items = items.filter((other) => other.id !== itemId);
        renderItems();
        closeItemForm();
    } catch (error) {
        console.error(error);
        addError.textContent = "Tresor-Server nicht erreichbar.";
    } finally {
        deleteButton.disabled = false;
    }
});


// ---------- Tresor sperren ----------

async function lockNow(message) {
    try {
       
        await vaultRequest("POST", "/vault/lock");
    } catch (error) {
        console.error(error);
    }
    lockVault(message);
}

document.getElementById("lock-button").addEventListener("click", () => lockNow("Tresor gesperrt."));


const AUTO_LOCK_MS = 15 * 60 * 1000;
let autoLockTimer = null;

function resetAutoLock() {
    clearTimeout(autoLockTimer);
    if (dek) {
        autoLockTimer = setTimeout(() => lockNow("Tresor nach 15 Minuten ohne Aktivität gesperrt."), AUTO_LOCK_MS);
    }
}

for (const type of ["click", "keydown", "mousemove", "scroll"]) {
    document.addEventListener(type, resetAutoLock, { passive: true });
}


// ---------- Zwei-Faktor-Anmeldung nachrüsten (nur alte Konten) ----------

const totpBanner = document.getElementById("totp-banner");
const totpForm = document.getElementById("totp-form");
const totpError = document.getElementById("totp-error");
const totpCodeInput = document.getElementById("totp-code");

// Nur im Arbeitsspeicher, nie im Storage
let totpSecret = null;

if (sessionStorage.getItem("totpEnabled") === "false") {
    totpSecret = newTotpSecret();
    showTotpSetup(
        document.getElementById("totp-qr"),
        document.getElementById("totp-secret"),
        sessionStorage.getItem("email") ?? "",
        totpSecret,
    );
    totpBanner.hidden = false;
}

function totpDone() {
    totpSecret?.fill(0);
    totpSecret = null;
    sessionStorage.setItem("totpEnabled", "true");
    totpBanner.hidden = true;
}

totpForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    totpError.textContent = "";

    const code = normalizeTotpCode(totpCodeInput.value);
    if (code === null) {
        totpError.textContent = "Bitte den 6-stelligen Code aus deiner Authenticator-App eingeben.";
        return;
    }

    const button = totpForm.querySelector("button");
    button.disabled = true;

    try {
        const response = await fetch(API_BASE + "/account/totp", {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + loginToken,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ secret: bytesToBase64(totpSecret), code: code }),
        });

        // 409: Konto hat schon TOTP, z. B. in einem anderen Tab eingerichtet
        if (response.status === 204 || response.status === 409) {
            totpDone();
            return;
        }
        if (response.status === 401) {
            goToLogin();
            return;
        }
        if (response.status === 400) {
            const error = await response.json().catch(() => ({}));
            if (error.reason === "invalid_totp") {
                totpCodeInput.value = "";
                totpError.textContent = "Der Code stimmt nicht. Warte auf den nächsten Code in der App und gib ihn ein.";
                return;
            }
        }
        totpError.textContent = "Gerade nicht möglich. Bitte versuche es später erneut.";
    } catch (error) {
        console.error(error);
        totpError.textContent = "Server nicht erreichbar.";
    } finally {
        button.disabled = false;
    }
});


// ---------- Konten auf Leaks prüfen (Breach-Service, POST /breach/account + GET /breach/account/jobs/{jobId}) ----------

const breachButton = document.getElementById("breach-button");
const breachUsernames = document.getElementById("breach-usernames");
const breachProgress = document.getElementById("breach-progress");
const breachError = document.getElementById("breach-error");
const breachList = document.getElementById("breach-list");

// Gleiche Grenzen wie im Breach-Service (routes/Validation.kt), sonst gibt es nur 400
const USERNAME_MIN = 3;
const USERNAME_MAX = 254;
// 429 beim Anlegen heißt: Queue im Service voll. Nicht endlos wiederholen.
const BREACH_MAX_RETRIES = 5;
// Der Service antwortet sofort mit einem Job, das Ergebnis wird abgefragt.
// Öfter fragen bringt nichts, der Worker schafft eh nur ~1 LeakCheck-Anfrage pro Sekunde.
const BREACH_POLL_MS = 1500;
// Danach gibt der Browser für dieses Konto auf. Der Job läuft im Service weiter (bis zu 1 h),
// beim nächsten Klick kommt das Ergebnis dann meist schon aus dem Cache.
const BREACH_MAX_WAIT_MS = 3 * 60 * 1000;

// "Prüfe 3 von 7 …", Wartehinweise werden hinten angehängt statt aufzusummieren
let breachProgressBase = "";

function showBreachProgress(extra) {
    breachProgress.textContent = extra ? `${breachProgressBase} (${extra})` : breachProgressBase;
}

// LeakCheck-Hash: SHA-256 über die E-Mail in Kleinbuchstaben, hex, die ersten 24 Zeichen
async function emailHash(email) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email.trim().toLowerCase()));
    return bytesToHex(new Uint8Array(digest)).slice(0, 24);
}

// LeakCheck durchsucht nur diese Zeichen, alles andere (Leerzeichen, Umlaute, alle anderen Sonderzeichen)
// lehnt es ab. Am 2026-11-03 mit allen druckbaren ASCII-Zeichen geprüft, gleiche Regel wie routes/Validation.kt.
const USERNAME_CHARS = /^[A-Za-z0-9._-]+$/;

function hasCheckableLength(name) {
    return name.length >= USERNAME_MIN && name.length <= USERNAME_MAX;
}

// Konto-E-Mail + alle verschiedenen "user"-Felder aus den Köpfen, ohne Duplikate.
// Enthält "@" → E-Mail (nur als Hash), sonst Benutzername (nur mit Zustimmung, geht im Klartext raus).
// Benutzernamen mit Zeichen, die LeakCheck nicht kann, gehen gar nicht erst raus und landen in unsupported.
function collectBreachChecks(withUsernames) {
    const checks = new Map();
    const unsupported = new Set();
    const values = [sessionStorage.getItem("email"), ...items.map((item) => item.user)];
    for (const raw of values) {
        const value = (raw ?? "").trim();
        if (!value) continue;
        if (value.includes("@")) {
            const key = "e:" + value.toLowerCase();
            if (!checks.has(key)) checks.set(key, { type: "email_hash", label: value.toLowerCase() });
        } else if (withUsernames && hasCheckableLength(value)) {
            if (!USERNAME_CHARS.test(value)) {
                unsupported.add(value);
                continue;
            }
            const key = "u:" + value;
            if (!checks.has(key)) checks.set(key, { type: "username", label: value });
        }
    }
    return { checks: [...checks.values()], unsupported: [...unsupported] };
}

function unsupportedItem(names) {
    return breachItem(`Nicht prüfbar, weil LeakCheck nur Buchstaben a–z, Ziffern und . _ - unterstützt: ${names.join(", ")}`, false);
}

// Beide Endpunkte wollen Login-Token und Tresor-Token, der Job-Abruf genauso wie das Anlegen
function breachRequest(method, path, body) {
    const headers = {
        "Authorization": "Bearer " + loginToken,
        "X-Vault-Token": vaultToken,
    };
    if (body) headers["Content-Type"] = "application/json";
    return fetch(BREACH_BASE + path, {
        method: method,
        headers: headers,
        body: body ? JSON.stringify(body) : undefined,
    });
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// Ergebnis: { found, fields, sources } bei Erfolg, null = nicht geprüft (Job failed, Queue voll, zu lange gewartet),
// "unsupported" = LeakCheck kann den Namen nicht durchsuchen (400), "locked" = Tresor gesperrt, dann bricht die Prüfung ab
async function checkOneAccount(check) {
    const value = check.type === "email_hash" ? await emailHash(check.label) : check.label;
    const job = await submitBreachJob(check.type, value);
    if (job === null || job === "locked" || job === "unsupported") return job;
    return await awaitBreachJob(job);
}

// Legt den Job an. Antwort ist sofort 202 mit { jobId, status, ... }, bei Cache-Treffer schon mit status "done".
async function submitBreachJob(type, value) {
    for (let attempt = 0; attempt <= BREACH_MAX_RETRIES; attempt++) {
        if (!vaultToken) return "locked";
        const response = await breachRequest("POST", "/breach/account", { type: type, value: value });

        if (response.ok) {
            return await response.json();
        }
        if (response.status === 429) {
            const seconds = Number(response.headers.get("Retry-After")) || 2;
            showBreachProgress(`Service ausgelastet, warte ${seconds} s …`);
            await sleep(seconds * 1000);
            continue;
        }
        // readVaultError leitet bei 401 unauthorized (Login abgelaufen) schon zum Login weiter
        const errorCode = await readVaultError(response);
        if (errorCode === "vault_locked") return "locked";
        // 400: Der Breach-Service lehnt Namen ab, die LeakCheck nicht durchsuchen kann (Leerzeichen, Umlaute, Sonderzeichen).
        // Ein neuer Versuch ändert daran nichts.
        if (response.status === 400) return "unsupported";
        return null;
    }
    return null;
}

// Fragt den Job ab, bis er done oder failed ist. Der Service wiederholt LeakCheck selbst (429, Ausfall),
// der Browser muss nur warten und darf nicht vorher abbrechen.
async function awaitBreachJob(job) {
    const deadline = Date.now() + BREACH_MAX_WAIT_MS;
    while (true) {
        if (job.status === "done") return job.result;
        if (job.status === "failed") return null;
        if (Date.now() > deadline) return null;

        showBreachProgress(job.status === "waiting_for_upstream"
            ? `LeakCheck antwortet gerade nicht, Versuch ${job.attempts} …`
            : null);
        await sleep(nextBreachPoll(job));

        if (!vaultToken) return "locked";
        const response = await breachRequest("GET", "/breach/account/jobs/" + encodeURIComponent(job.jobId));
        if (!response.ok) {
            const errorCode = await readVaultError(response);
            if (errorCode === "vault_locked") return "locked";
            // 404: Job weg, z. B. weil der Service neu gestartet wurde (die Queue liegt nur im Speicher)
            return null;
        }
        job = await response.json();
    }
}

// Beim Warten auf LeakCheck steht in nextAttemptAt, wann der nächste Versuch kommt. Vorher fragen ist sinnlos,
// aber höchstens 10 s still sein, damit die Anzeige nicht hängt.
function nextBreachPoll(job) {
    if (!job.nextAttemptAt) return BREACH_POLL_MS;
    const untilRetry = Date.parse(job.nextAttemptAt) - Date.now();
    return Math.min(Math.max(untilRetry, BREACH_POLL_MS), 10_000);
}

function breachItem(text, hit) {
    const li = document.createElement("li");
    li.textContent = text;
    if (hit) li.classList.add("breach-hit");
    return li;
}

function describeBreach(check, result) {
    const who = check.label;
    if (result === null) {
        return breachItem(`${who}: nicht geprüft (LeakCheck gerade nicht erreichbar)`, false);
    }
    if (result === "unsupported") {
        return breachItem(`${who}: nicht prüfbar (LeakCheck unterstützt nur Buchstaben a–z, Ziffern und . _ -)`, false);
    }
    if (result.found === 0) {
        return breachItem(`${who}: in keinem bekannten Leak`, false);
    }
    const sources = result.sources
        .map((source) => source.date ? `${source.name} (${source.date})` : source.name)
        .join(", ");
    const fields = result.fields.length ? ` Betroffen: ${result.fields.join(", ")}.` : "";
    return breachItem(`${who}: in ${result.found} Leak(s) gefunden.${fields} Quellen: ${sources || "unbekannt"}`, true);
}

breachButton.addEventListener("click", async () => {
    breachError.textContent = "";
    breachList.replaceChildren();

    // Nur bei entsperrtem Tresor: Die Benutzernamen stammen aus dem Tresor, und der Breach-Service will den Tresor-Token
    if (!vaultToken) {
        breachError.textContent = "Bitte entsperre zuerst deinen Tresor.";
        return;
    }

    const { checks, unsupported } = collectBreachChecks(breachUsernames.checked);
    if (checks.length === 0) {
        breachError.textContent = "Keine E-Mails oder Benutzernamen zum Prüfen gefunden.";
        if (unsupported.length) breachList.append(unsupportedItem(unsupported));
        return;
    }

    breachButton.disabled = true;
    breachProgress.hidden = false;
    let hits = 0;

    try {
        // Der Reihe nach, LeakCheck erlaubt nur 1 Anfrage pro Sekunde für den ganzen Server
        for (let i = 0; i < checks.length; i++) {
            breachProgressBase = `Prüfe ${i + 1} von ${checks.length} …`;
            showBreachProgress(null);
            const result = await checkOneAccount(checks[i]);
            if (result === "locked") {
                lockVault(LOCKED_MESSAGE);
                breachList.replaceChildren();
                breachError.textContent = "Prüfung abgebrochen, der Tresor wurde gesperrt.";
                return;
            }
            if (result && result.found > 0) hits++;
            breachList.append(describeBreach(checks[i], result));
        }
        if (unsupported.length) breachList.append(unsupportedItem(unsupported));
        breachProgress.textContent = hits === 0
            ? `Fertig: ${checks.length} geprüft, nichts gefunden.`
            : `Fertig: ${hits} von ${checks.length} in Leaks gefunden. Ändere dort am besten die Passwörter.`;
    } catch (error) {
        console.error(error);
        breachError.textContent = "Breach-Service nicht erreichbar.";
    } finally {
        breachButton.disabled = false;
    }
});
