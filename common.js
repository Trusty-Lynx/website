const API_BASE = "https://auth.nexvent.de";
const VAULT_BASE = "https://vault.nexvent.de"; 

const KDF = { alg: "argon2id", m: 65536, t: 3, p: 1, len: 32 };



function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function bytesToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}


async function getDeviceId() {
    const publicKey = await getDevicePublicKey();
    return publicKey
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
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
    return bytesToBase64(loginKey);
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

async function signRequest(method, path, body) {
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const bodyHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body || ""));
    const message = method + "|" + path + "|" + timestamp + "|" + bytesToHex(new Uint8Array(bodyHash));

    await getDevicePublicKey();
    const keyPair = await loadDeviceKeyPair();
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        new TextEncoder().encode(message)
    );

    return {
        "X-Device-Id": await getDeviceId(),
        "X-Timestamp": timestamp,
        "X-Device-Sig": bytesToBase64(new Uint8Array(signature)),
    };
}

function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}



