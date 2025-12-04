<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\RequestStack;

class CookiePreferencesService
{
    public function __construct(private RequestStack $requestStack) {}

    public function getPreferences(): ?array
    {
        $request = $this->requestStack->getCurrentRequest();
        if (!$request) {
            return null;
        }

        $cookie = $request->cookies->get('cookie_preferences');

        if (!$cookie) {
            return null;
        }

        return json_decode($cookie, true);
    }
}
