<?php

// src/EventListener/CspNonceListener.php
namespace App\EventListener;

use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpFoundation\RequestStack;
use Twig\Environment;

class CSPNonceListener
{
    private $twig;
    public function __construct(Environment $twig)
    {
        $this->twig = $twig;
    }

    public function onKernelController(ControllerEvent $event)
    {
        $nonce = base64_encode(random_bytes(16));
        $this->twig->addGlobal('csp_nonce', $nonce);
    }
}
