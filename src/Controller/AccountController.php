<?php 

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class AccountController extends AbstractController
{
    #[Route('/account/login', name: 'account_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('account/login.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error'         => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }

    #[Route('/account/register', name: 'account_register', methods: ['POST'])]
    public function register(
        Request $request,
        UserPasswordHasherInterface $hasher,
        EntityManagerInterface $em
    ): Response
    {
        // Récupération des champs
        $name     = $request->request->get('name');
        $surname  = $request->request->get('surname');
        $email    = $request->request->get('email');
        $password = $request->request->get('password');
        $adresse  = $request->request->get('adresse');

        // Vérifie email déjà existant
        if ($em->getRepository(User::class)->findOneBy(['email' => $email])) {
            $this->addFlash('error', 'Un compte existe déjà avec cet email.');
            return $this->redirectToRoute('account_login');
        }

        // Liste des erreurs
        $errors = [];

        // Vérifications du mot de passe
        if (strlen($password) < 12) {
            $errors[] = "Le mot de passe doit contenir au moins 12 caractères.";
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins 1 lettre minuscule.";
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins 1 lettre majuscule.";
        }
        if (!preg_match('/\d/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins 1 chiffre.";
        }

        // Caractères spéciaux → version 100% sûre
        if (!preg_match('/[!@#$%^&*()_\-+={}[\]|\\:;"\'<>,.?~`]/', $password)) {
            $errors[] = "Le mot de passe doit contenir au moins 1 caractère spécial.";
        }

        // Si des erreurs → renvoyer
        if (!empty($errors)) {
            foreach ($errors as $err) {
                $this->addFlash('error', $err);
            }
            return $this->redirectToRoute('account_login');
        }

        // Création du user
        $user = new User();
        $user->setName($name)
             ->setSurname($surname)
             ->setEmail($email)
             ->setAdresse($adresse)
             ->setPassword(
                 $hasher->hashPassword($user, $password)
             );

        // Sauvegarde
        $em->persist($user);
        $em->flush();

        $this->addFlash('success', 'Compte créé avec succès ! Vous pouvez maintenant vous connecter.');
        return $this->redirectToRoute('account_login');
    }

    #[Route('/account', name: 'account')]
    public function account(): Response
    {
        $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');
        return $this->render('account/index.html.twig');
    }

    #[Route('/account/logout', name: 'account_logout')]
    public function logout(): void
    {
        // Géré automatiquement par Symfony Security
    }

    #[Route('/account/update', name: 'account_update', methods: ['POST'])]
    public function update(Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');

        /** @var \App\Entity\User $user */
        $user = $this->getUser();

        $name = $request->request->get('name');
        $surname = $request->request->get('surname');
        $email = $request->request->get('email');
        $adresse = $request->request->get('adresse');

        // Vérifie si l’email est déjà utilisé par un autre utilisateur
        $existingUser = $em->getRepository(User::class)->findOneBy(['email' => $email]);
        if ($existingUser && $existingUser->getId() !== $user->getId()) {
            $this->addFlash('error', 'Cet email est déjà utilisé par un autre compte.');
            return $this->redirectToRoute('account');
        }

        $user->setName($name)
            ->setSurname($surname)
            ->setEmail($email)
            ->setAdresse($adresse);

        $em->persist($user);
        $em->flush();

        $this->addFlash('success', 'Vos informations ont été mises à jour avec succès.');
        return $this->redirectToRoute('account');
    }


}
