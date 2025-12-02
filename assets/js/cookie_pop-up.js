document.addEventListener('DOMContentLoaded', () => {
    const popup = document.getElementById('cookie-popup');
    const overlay = document.getElementById('cookie-overlay');
    const form = document.getElementById('cookie-form');
    const checkbox = document.getElementById('cookie-consent');

    if (!popup || !overlay || !form || !checkbox) {
        return;
    }

    // Si déjà accepté -> rien afficher
    if (localStorage.getItem('cookieConsent') === 'true') {
        popup.setAttribute('aria-hidden', 'true');
        overlay.setAttribute('aria-hidden', 'true');
        return;
    }

    // Affiche popup + overlay
    popup.setAttribute('aria-hidden', 'false');
    overlay.setAttribute('aria-hidden', 'false');

    form.addEventListener('submit', (e) => {
        e.preventDefault();

        if (!checkbox.checked) {
            alert('Vous devez accepter les cookies pour continuer.');
            return;
        }

        localStorage.setItem('cookieConsent', 'true');

        // Masque les deux
        popup.setAttribute('aria-hidden', 'true');
        overlay.setAttribute('aria-hidden', 'true');
    });
});