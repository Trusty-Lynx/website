const API_BASE = "https://auth.nexvent.de";
const VAULT_BASE = "https://vault.nexvent.de";

const KDF = { alg: "argon2id", m: 65536, t: 3, p: 1, len: 32 };


function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}


// Früher gab es einen Geräteschlüssel in IndexedDB. Einmal löschen, damit kein privater Schlüssel liegen bleibt.
function removeOldDeviceData() {
    indexedDB.deleteDatabase("trusty-lynx");
    for (const key of Object.keys(localStorage)) {
        if (key === "deviceId" || key.startsWith("deviceRegistered:")) {
            localStorage.removeItem(key);
        }
    }
}

removeOldDeviceData();


// loginKey = HKDF(Argon2id(Kontopasswort, salt_login), "TL-login-v1")
async function deriveLoginKey(password, saltBytes, kdf) {
    const lk = await hashwasm.argon2id({
        password: password,
        salt: saltBytes,
        parallelism: kdf.p,
        iterations: kdf.t,
        memorySize: kdf.m,
        hashLength: kdf.len,
        outputType: "binary",
    });
    const loginKey = await hkdf(lk, "TL-login-v1");
    const result = bytesToBase64(loginKey);
    lk.fill(0);
    loginKey.fill(0);
    return result;
}

// kdf vom Server muss genau den Standardwerten entsprechen, sonst könnte ein Server schwächere Parameter unterschieben
function isDefaultKdf(kdf) {
    return kdf !== null && typeof kdf === "object"
        && kdf.alg === KDF.alg
        && kdf.m === KDF.m
        && kdf.t === KDF.t
        && kdf.p === KDF.p
        && kdf.len === KDF.len;
}

// HKDF-SHA256 laut Verschlüsselung.md: Salt = 32 × 00, Länge 32 Byte, info = Etikett als UTF-8
async function hkdf(keyBytes, label) {
    const key = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(32),
            info: new TextEncoder().encode(label),
        },
        key,
        256
    );
    return new Uint8Array(bits);
}
