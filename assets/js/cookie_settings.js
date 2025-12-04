// assets/js/cookie_settings.js
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById("cookie-settings-form");
    const status = document.getElementById("cookie-status");
    const resetBtn = document.getElementById("reset-cookies");

    if (!form || !status || !resetBtn) return;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const necessary = form.necessary.checked;
        const analytics = form.analytics.checked;

        if (!necessary) {
            alert("Vous devez accepter les cookies nécessaires pour naviguer sur le site.");
            return;
        }

        try {
            const res = await fetch("/cookie-consent/accept", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ necessary, analytics })
            });
            const data = await res.json();
            status.innerText = res.ok ? data.message : data.error || "Erreur";
        } catch {
            status.innerText = "Erreur réseau.";
        }
    });

    resetBtn.addEventListener("click", async () => {
        try {
            const res = await fetch("/cookie-consent/reset", { method: "POST" });
            const data = await res.json();
            if (res.ok) {
                status.innerText = data.message;
                form.necessary.checked = false;
                form.analytics.checked = false;

                // Faire réapparaître le pop-up
                const popup = document.getElementById("cookie-popup");
                const overlay = document.getElementById("cookie-overlay");
                if (popup && overlay) {
                    popup.setAttribute("aria-hidden", "false");
                    overlay.setAttribute("aria-hidden", "false");
                }
            } else {
                status.innerText = data.error || "Impossible de réinitialiser";
            }
        } catch {
            status.innerText = "Erreur réseau.";
        }
    });
});
