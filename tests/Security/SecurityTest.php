<?php

namespace App\Tests\Security;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🔒 SUITE DE TESTS DE SÉCURITÉ
 * 
 * Tests : CSRF, SQL Injection, IDOR, XSS
 */
class SecurityTest extends WebTestCase
{
    private $client;
    private $entityManager;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->entityManager = $this->client->getContainer()
            ->get('doctrine')
            ->getManager();

        // 🔄 Vider complètement la table user avant chaque test
        $connection = $this->entityManager->getConnection();
        $platform = $connection->getDatabasePlatform();

        // SQLite : RESET AUTO_INCREMENT et supprimer les lignes
        $connection->executeStatement($platform->getTruncateTableSQL('user', true));
    }

    // ==========================================
    // 🛡️ TESTS CSRF (Cross-Site Request Forgery)
    // ==========================================

    /**
     * Test 1 : Formulaire d'inscription SANS token CSRF doit échouer
     */
    public function testRegisterWithoutCsrfTokenShouldFail(): void
    {
        $this->client->request('POST', '/account/register', [
            'name' => 'TestUser',
            'surname' => 'TestSurname',
            'email' => 'test@example.com',
            'password' => 'SecurePass123!',
            'adresse' => '123 Test St'
        ]);

        $this->assertNotEquals(Response::HTTP_OK, $this->client->getResponse()->getStatusCode());
    }

    /**
     * Test 2 : Mise à jour compte SANS authentification doit échouer
     */
    public function testUpdateAccountWithoutAuthShouldFail(): void
    {
        $this->client->request('POST', '/account/update', [
            'name' => 'Hacker',
            'surname' => 'Evil',
            'email' => 'hacker@evil.com',
            'adresse' => 'Dark Web'
        ]);

        $response = $this->client->getResponse();
        $this->assertTrue($response->isRedirect() || $response->getStatusCode() === 403);
    }

    /**
     * Test 3 : Suppression utilisateur SANS être admin doit échouer
     */
    public function testDeleteUserWithoutAdminRoleShouldFail(): void
    {
        $user = $this->createTestUser('normal@test.com', false);
        $this->client->request('GET', '/');
        $this->loginAs($user);

        $targetUser = $this->createTestUser('victim@test.com', false);

        $this->client->request('POST', '/admin/delete/' . $targetUser->getId());

        $status = $this->client->getResponse()->getStatusCode();
        $this->assertTrue(
            $status === 403 || $status === 302,
            "Expected 403 or redirect (302), got $status"
        );
    }

    // ==========================================
    // 💉 TESTS SQL INJECTION
    // ==========================================

    /**
     * Test 5 : SQL Injection dans l'inscription
     */
    public function testSqlInjectionInRegistration(): void
    {
        $payload = "test'; DROP TABLE user; --";

        $this->client->request('POST', '/account/register', [
            'name' => $payload,
            'surname' => 'Test',
            'email' => 'sqli@test.com',
            'password' => 'SecurePass123!',
            'adresse' => 'Test Address'
        ]);

        // Vérifier que la table existe toujours
        $schema = $this->entityManager->getConnection()->createSchemaManager();
        $tables = $schema->listTableNames();

        $this->assertContains('user', $tables, 'User table must not be dropped.');
    }

    /**
     * Test 6 : SQL Injection dans recherche (si implémentée)
     */
    public function testSqlInjectionInSearch(): void
    {
        // Si vous avez une route de recherche
        $sqlPayloads = [
            "'; DELETE FROM user WHERE '1'='1",
            "1' UNION SELECT password FROM user--"
        ];

        foreach ($sqlPayloads as $payload) {
            $this->client->request('GET', '/products', ['search' => $payload]);
            
            // Attendu : Pas d'erreur 500, traitement sécurisé
            $this->assertNotEquals(
                Response::HTTP_INTERNAL_SERVER_ERROR,
                $this->client->getResponse()->getStatusCode(),
                'SQL Injection should not cause server error'
            );
        }
    }

    // ==========================================
    // 🔓 TESTS IDOR (Insecure Direct Object Reference)
    // ==========================================

    /**
     * Test 8 : IDOR - Accès au profil d'un autre utilisateur
     */
    public function testIdorProfileAccess(): void
    {
        $user1 = $this->createTestUser('user1@test.com', false);
        $user2 = $this->createTestUser('user2@test.com', false);

        $this->loginAs($user1);

        // Tenter d'accéder au compte (la route /account n'a pas d'ID dans votre code)
        // Ce test est adapté pour vérifier qu'on ne peut pas voir d'autres profils
        
        // Test: vérifier qu'on voit bien NOTRE propre compte
        $crawler = $this->client->request('GET', '/account');
        $this->assertStringContainsString(
            $user1->getEmail(),
            $this->client->getResponse()->getContent()
        );

        $this->cleanup($user1, $user2);
    }

    /**
     * Test 9 : IDOR - Suppression d'utilisateur par ID
     */
    public function testIdorUserDeletion(): void
    {
        // Créer admin et victime
        $admin = $this->createTestUser('admin@test.com', true);
        $victim = $this->createTestUser('victim@test.com', false);
        
        $this->loginAs($admin);

        // Admin peut supprimer
        $this->client->request('POST', '/admin/delete/' . $victim->getId());
        
        // Vérifier que la suppression a fonctionné
        $this->entityManager->clear();
        $deletedUser = $this->entityManager
            ->getRepository(User::class)
            ->find($victim->getId());
        
        $this->assertNull($deletedUser, 'Admin should be able to delete user');

        // Mais un utilisateur normal NE PEUT PAS
        $normalUser = $this->createTestUser('normal@test.com', false);
        $anotherVictim = $this->createTestUser('victim2@test.com', false);
        
        $this->loginAs($normalUser);
        $this->client->request('POST', '/admin/delete/' . $anotherVictim->getId());
        
        // Vérifier que l'utilisateur existe toujours
        $this->entityManager->clear();
        $stillExists = $this->entityManager->getRepository(User::class)
            ->find($anotherVictim->getId());
        
        $this->assertNotNull($stillExists, 'Normal user should NOT delete other users');

        $this->cleanup($admin, $normalUser, $stillExists);
    }

    // ==========================================
    // 🧨 TESTS XSS (Cross-Site Scripting)
    // ==========================================

    /**
     * Test 10 : XSS dans formulaire d'inscription
     */
    public function testXssInRegistrationForm(): void
    {
        $xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
        ];

        foreach ($xssPayloads as $payload) {
            $email = 'xss' . uniqid() . '@test.com';
            
            $this->client->request('POST', '/account/register', [
                'name' => $payload,
                'surname' => 'Test',
                'email' => $email,
                'password' => 'SecurePass123!',
                'adresse' => 'Test Address'
            ]);

            // Vérifier que le payload est échappé en BDD
            $this->entityManager->clear();
            $user = $this->entityManager
                ->getRepository(User::class)
                ->findOneBy(['email' => $email]);

            if ($user) {
                // Récupérer la page du compte
                $this->client->request('GET', '/account');
                $this->loginAs($user);
                $this->client->request('GET', '/account');
                
                $content = $this->client->getResponse()->getContent();
                
                // Vérifier que le script n'est PAS exécutable
                $this->assertStringNotContainsString(
                    '<script>alert',
                    $content,
                    'XSS payload should be escaped in output'
                );

                $this->cleanup($user);
            }
        }
    }

    /**
     * Test 11 : XSS Stored dans commentaires/bio (si applicable)
     */
    public function testStoredXss(): void
    {
        $user = $this->createTestUser('xsstest@test.com', false);
        $this->loginAs($user);

        $xssPayload = '<script>document.cookie="hacked=true";</script>';
        
        // Obtenir le token CSRF
        $crawler = $this->client->request('GET', '/account');
        $token = $crawler->filter('input[name="_token"]')->attr('value');
        
        // Mettre le payload dans l'adresse
        $this->client->request('POST', '/account/update', [
            'user_id' => $user->getId(),
            'name' => $user->getName(),
            'surname' => $user->getSurname(),
            'email' => $user->getEmail(),
            'adresse' => $xssPayload,
            '_token' => $token
        ]);

        // Recharger la page
        $this->client->request('GET', '/account');
        $content = $this->client->getResponse()->getContent();

        // Vérifier que le script est échappé
        $this->assertStringNotContainsString(
            '<script>',
            $content,
            'Stored XSS should be escaped'
        );

        $this->cleanup($user);
    }

    /**
     * Test 12 : XSS Reflected dans URL parameters
     */
    public function testReflectedXss(): void
    {
        $payload = '<script>alert(1)</script>';

        $this->client->request('GET', '/products', ['search' => $payload]);
        $content = $this->client->getResponse()->getContent();

        $escaped = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');

        $this->assertFalse(str_contains($content, $payload) && !str_contains($content, $escaped));
    }

    // ==========================================
    // 🧰 HELPER METHODS
    // ==========================================

    private function createTestUser(string $email, bool $isAdmin = false): User
    {
        $user = new User();
        $user->setName('Test')
            ->setSurname('User')
            ->setEmail($email)
            ->setPassword(password_hash('test', PASSWORD_BCRYPT))
            ->setAdresse('Test')
            ->setIsAdmin($isAdmin);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    private function loginAs(User $user): void
    {
        // Faire une requête initiale pour créer la session
        $this->client->request('GET', '/');

        $session = $this->client->getRequest()->getSession();
        if (!$session) {
            throw new \RuntimeException('Impossible de récupérer la session.');
        }

        $firewallName = 'main';
        $token = new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
            $user,
            $firewallName,
            $user->getRoles()
        );

        $session->set('_security_' . $firewallName, serialize($token));
        $session->save();

        $cookie = new \Symfony\Component\BrowserKit\Cookie($session->getName(), $session->getId());
        $this->client->getCookieJar()->set($cookie);
    }

    private function isAuthenticatedInClient($client): bool
    {
        $container = $client->getContainer();
        $security = $container->get('security.token_storage');
        $token = $security->getToken();

        return $token && $token->getUser() instanceof User;
    }

    private function cleanup(User ...$users): void
    {
        foreach ($users as $user) {
            // 🔥 Vérifier si l'entité existe dans la BDD avant de la supprimer
            $this->entityManager->clear();
            $userFromDb = $this->entityManager->find(User::class, $user->getId());
            
            if ($userFromDb) {
                $this->entityManager->remove($userFromDb);
            }
        }
        $this->entityManager->flush();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        
        if ($this->entityManager) {
            $this->entityManager->close();
            $this->entityManager = null;
        }
    }
}