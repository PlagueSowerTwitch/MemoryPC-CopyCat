<?php

// src/EventListener/CspListener.php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\ResponseEvent;

class CSPListener
{
    public function onKernelResponse(ResponseEvent $event)
    {
        $response = $event->getResponse();

        // Exemple de politique CSP
        $csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';";

        $response->headers->set('Content-Security-Policy', $csp);
    }
}
