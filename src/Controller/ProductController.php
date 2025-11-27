<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProductController extends AbstractController
{
    #[Route('/products', name: 'product_list')]
    public function index(): Response
    {
        return $this->render('product/index.html.twig');
    }

    #[Route('/product/{id}', name: 'product_show')]
    public function show(int $id): Response
    {
        return $this->render('product/show.html.twig', [
            'id' => $id,
        ]);
    }
}
