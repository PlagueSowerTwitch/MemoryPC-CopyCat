document.addEventListener('DOMContentLoaded', () => {
    const popup = document.getElementById('cookie-popup');
    const overlay = document.getElementById('cookie-overlay');
    const form = document.getElementById('cookie-form');
    const checkbox = document.getElementById('cookie-consent');

    if (!popup || !overlay || !form || !checkbox) {
        return;
    }

    // ------------------------
    // Fonction pour afficher/masquer popup
    // ------------------------
    const showPopup = () => {
        popup.removeAttribute('aria-hidden');
        overlay.removeAttribute('aria-hidden');
        // Pour l'accessibilité, focus sur le checkbox
        checkbox.focus();
    };

    const hidePopup = () => {
        popup.setAttribute('aria-hidden', 'true');
        overlay.setAttribute('aria-hidden', 'true');
    };

    // ------------------------
    // Gestion du consentement
    // ------------------------
    const consentKey = 'cookieConsent';

    // Vérifie si serveur a forcé le reset (via un attribut data-reset sur body)
    const forceReset = document.body.dataset.cookieReset === 'true';

    if (forceReset) {
        localStorage.removeItem(consentKey);
    }

    // Affiche popup si pas encore accepté
    if (localStorage.getItem(consentKey) !== 'true') {
        showPopup();
    } else {
        hidePopup();
    }

    // ------------------------
    // Événement submit
    // ------------------------
    form.addEventListener('submit', (e) => {
        e.preventDefault();

        if (!checkbox.checked) {
            alert('Vous devez accepter les cookies pour continuer.');
            checkbox.focus();
            return;
        }

        localStorage.setItem(consentKey, 'true');
        hidePopup();
    });
});