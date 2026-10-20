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
