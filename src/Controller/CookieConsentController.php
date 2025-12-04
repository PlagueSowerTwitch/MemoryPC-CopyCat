<?php
// src/Controller/CookieConsentController.php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;

class CookieConsentController extends AbstractController
{
    private CsrfTokenManagerInterface $csrf;

    public function __construct(CsrfTokenManagerInterface $csrf)
    {
        $this->csrf = $csrf;
    }

    #[Route('/cookie-consent/accept', name: 'cookie_consent_accept', methods: ['POST'])]
    public function accept(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        if (!isset($data['necessary']) || $data['necessary'] !== true) {
            return new JsonResponse([
                'error' => 'Vous devez accepter les cookies nécessaires pour naviguer sur le site.'
            ], 400);
        }

        $preferences = [
            'necessary' => true,
            'analytics' => $data['analytics'] ?? false,
            'set_at' => time()
        ];

        $cookie = Cookie::create('cookie_preferences')
            ->withValue(json_encode($preferences))
            ->withExpires(strtotime('+30 minutes'))
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withSameSite('Strict')
            ->withPath('/');

        $response = new JsonResponse([
            'success' => true,
            'message' => 'Vos préférences ont été enregistrées.'
        ]);

        $response->headers->setCookie($cookie);

        return $response;
    }

    #[Route('/cookie-consent/reset', name: 'cookie_consent_reset', methods: ['POST'])]
    public function reset(): JsonResponse
    {
        $cookie = Cookie::create('cookie_preferences')
            ->withValue('')
            ->withExpires(1)
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withSameSite('Strict')
            ->withPath('/');

        $response = new JsonResponse([
            'success' => true,
            'message' => 'Vos préférences ont été réinitialisées.'
        ]);

        $response->headers->setCookie($cookie);

        return $response;
    }

    #[Route('/cookie-consent/revoke', name: 'cookie_consent_revoke', methods: ['POST'])]
    public function revoke(Request $request): JsonResponse
    {
        $csrfHeader = $request->headers->get('X-CSRF-TOKEN');

        if (!$this->csrf->isTokenValid(new CsrfToken('cookie_consent', $csrfHeader))) {
            return new JsonResponse(['error' => 'Invalid CSRF token'], Response::HTTP_FORBIDDEN);
        }

        // Destroy cookie
        $cookie = Cookie::create(
            'cookie_consent',
            '',
            time() - 1800, 
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_LAX
        );

        $response = new JsonResponse(['revoked' => true]);
        $response->headers->setCookie($cookie);

        return $response;
    }
}
