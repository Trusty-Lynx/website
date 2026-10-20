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
