<?php

namespace App\EventListener;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Twig\Environment;

class ExceptionListener
{
    private $twig;

    public function __construct(Environment $twig)
    {
        $this->twig = $twig;
    }

    public function onKernelException(ExceptionEvent $event)
    {
        $exception = $event->getThrowable();

        // On ne cible que les 404
        if ($exception instanceof NotFoundHttpException) {
            $response = new Response(
                $this->twig->render('bundles/TwigBundle/Exception/error404.html.twig'),
                404
            );

            $event->setResponse($response);
        }
    }
}
