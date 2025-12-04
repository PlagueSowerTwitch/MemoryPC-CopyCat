document.addEventListener('DOMContentLoaded', () => {
    const popup = document.getElementById('cookie-popup');
    const overlay = document.getElementById('cookie-overlay');
    const form = document.getElementById('cookie-form');
    const necessaryCheckbox = document.getElementById('cookie-necessary');
    const analyticsCheckbox = document.getElementById('cookie-analytics');
    const statusMsg = document.getElementById('cookie-status');
    const resetBtn = document.getElementById('reset-cookies');

    if (!popup || !overlay || !form || !necessaryCheckbox || !analyticsCheckbox || !statusMsg || !resetBtn) {
        return;
    }

    // -------------------------------
    // Fonctions pour afficher/masquer le pop-up
    // -------------------------------
    const showPopup = () => {
        popup.setAttribute('aria-hidden', 'false');
        overlay.setAttribute('aria-hidden', 'false');
        necessaryCheckbox.focus();
    };

    const hidePopup = () => {
        popup.setAttribute('aria-hidden', 'true');
        overlay.setAttribute('aria-hidden', 'true');
    };

    // -------------------------------
    // Vérifie si les cookies ont déjà été acceptés côté serveur
    // -------------------------------
    const cookieConsent = document.body.dataset.cookieConsent === 'true';
    const forceReset = document.body.dataset.cookieReset === 'true';

    if (!cookieConsent || forceReset) {
        showPopup();
    } else {
        hidePopup();
    }

    // -------------------------------
    // Helper CSRF (si nécessaire)
    // -------------------------------
    const getCsrfToken = () => {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : '';
    };

    // -------------------------------
    // Submit du formulaire de consentement
    // -------------------------------
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!necessaryCheckbox.checked) {
            alert('Vous devez accepter les cookies nécessaires pour naviguer sur le site.');
            necessaryCheckbox.focus();
            return;
        }

        try {
            const resp = await fetch('/cookie-consent/accept', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': getCsrfToken()
                },
                body: JSON.stringify({
                    necessary: necessaryCheckbox.checked,
                    analytics: analyticsCheckbox.checked
                })
            });

            const data = await resp.json();

            if (resp.ok) {
                statusMsg.innerText = data.message || 'Vos préférences ont été enregistrées.';
                hidePopup();
            } else {
                statusMsg.innerText = data.error || 'Impossible d’enregistrer vos préférences.';
            }
        } catch (err) {
            console.error('Erreur lors de l’enregistrement des cookies', err);
            statusMsg.innerText = 'Erreur réseau lors de l’enregistrement.';
        }
    });

    // -------------------------------
    // Réinitialiser les cookies
    // -------------------------------
    resetBtn.addEventListener('click', async () => {
        try {
            const resp = await fetch('/cookie-consent/reset', {
                method: 'POST',
                headers: {
                    'X-CSRF-TOKEN': getCsrfToken()
                }
            });

            const data = await resp.json();

            if (resp.ok) {
                statusMsg.innerText = data.message || 'Vos préférences ont été réinitialisées.';
                necessaryCheckbox.checked = false;
                analyticsCheckbox.checked = false;

                // Réaffiche le pop-up pour forcer l’acceptation
                showPopup();
            } else {
                statusMsg.innerText = data.error || 'Impossible de réinitialiser vos préférences.';
            }
        } catch (err) {
            console.error('Erreur lors de la réinitialisation des cookies', err);
            statusMsg.innerText = 'Erreur réseau lors de la réinitialisation.';
        }
    });
});