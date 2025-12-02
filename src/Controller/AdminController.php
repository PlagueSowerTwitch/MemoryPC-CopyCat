<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/admin')]
class AdminController extends AbstractController
{
    #[Route('/', name: 'admin_dashboard')]
    public function index(EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        // Récupère tous les utilisateurs non-admin
        $users = $em->getRepository(User::class)->findBy(['isAdmin' => false]);

        return $this->render('admin/index.html.twig', [
            'users' => $users
        ]);
    }

    #[Route('/delete/{id}', name: 'admin_delete_user', methods: ['POST'])]
    public function delete(User $user, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if ($user->isAdmin()) {
            $this->addFlash('error', 'Impossible de supprimer un autre admin.');
            return $this->redirectToRoute('admin_dashboard');
        }

        $em->remove($user);
        $em->flush();

        $this->addFlash('success', 'Utilisateur supprimé avec succès.');
        return $this->redirectToRoute('admin_dashboard');
    }

    #[Route('/create-admin', name: 'admin_create_admin', methods: ['POST'])]
    public function createAdmin(Request $request, UserPasswordHasherInterface $hasher, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $email = $request->request->get('email');
        $password = $request->request->get('password');
        $name = $request->request->get('name');
        $surname = $request->request->get('surname');
        $adresse = $request->request->get('adresse');

        // Vérifie si l'email existe déjà
        $existing = $em->getRepository(User::class)->findOneBy(['email' => $email]);
        if ($existing) {
            $this->addFlash('error', 'Un utilisateur existe déjà avec cet email.');
            return $this->redirectToRoute('admin_dashboard');
        }

        $user = new User();
        $user->setEmail($email)
             ->setName($name)
             ->setSurname($surname)
             ->setAdresse($adresse)
             ->setIsAdmin(true)
             ->setPassword($hasher->hashPassword($user, $password));

        $em->persist($user);
        $em->flush();

        $this->addFlash('success', 'Nouvel admin créé avec succès !');
        return $this->redirectToRoute('admin_dashboard');
    }
}
