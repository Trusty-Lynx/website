const API_BASE = "/api";
const KDF = { alg: "argon2id", m: 65536, t: 3, p: 1, len: 32 };



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


async function deriveLoginKey(password, saltBytes, kdf) {
    const keyBytes = await hashwasm.argon2id({
        password: password,
        salt: saltBytes,
        parallelism: kdf.p,
        iterations: kdf.t,
        memorySize: kdf.m,
        hashLength: kdf.len,
        outputType: "binary",
    });
    return bytesToBase64(keyBytes);
}



