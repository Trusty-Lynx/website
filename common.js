const API_BASE = "https://auth.nexvent.de";
const VAULT_BASE = "https://vault.nexvent.de";
const BREACH_BASE = "https://breach.nexvent.de";

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

function removeOldDeviceData() {
    indexedDB.deleteDatabase("trusty-lynx");
    for (const key of Object.keys(localStorage)) {
        if (key === "deviceId" || key.startsWith("deviceRegistered:")) {
            localStorage.removeItem(key);
        }
    }
}

removeOldDeviceData();

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

function isDefaultKdf(kdf) {
    return kdf !== null && typeof kdf === "object"
        && kdf.alg === KDF.alg
        && kdf.m === KDF.m
        && kdf.t === KDF.t
        && kdf.p === KDF.p
        && kdf.len === KDF.len;
}

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

const TOTP_ISSUER = "TrustyLynx";

function newTotpSecret() {
    return crypto.getRandomValues(new Uint8Array(20));
}

function base32Encode(bytes) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let out = "";
    for (const byte of bytes) {
        value = ((value << 8) | byte) & 0xffff;
        bits += 8;
        while (bits >= 5) {
            out += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        out += alphabet[(value << (5 - bits)) & 31];
    }
    return out;
}

function totpUri(email, secretBytes) {
    const label = encodeURIComponent(TOTP_ISSUER) + ":" + encodeURIComponent(email);
    const params = new URLSearchParams({
        secret: base32Encode(secretBytes),
        issuer: TOTP_ISSUER,
        algorithm: "SHA1",
        digits: "6",
        period: "30",
    });
    return "otpauth://totp/" + label + "?" + params.toString();
}

function formatTotpSecret(secretBytes) {
    return base32Encode(secretBytes).match(/.{1,4}/g).join(" ");
}

function normalizeTotpCode(input) {
    const code = input.replace(/\s/g, "");
    return /^\d{6}$/.test(code) ? code : null;
}

function showTotpSetup(qrElement, secretElement, email, secretBytes) {
    const qr = qrcode(0, "M");
    qr.addData(totpUri(email, secretBytes));
    qr.make();
    qrElement.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4 });
    secretElement.textContent = formatTotpSecret(secretBytes);
}
