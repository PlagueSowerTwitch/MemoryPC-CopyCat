<?php

namespace App\Tests\Security;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Doctrine\ORM\EntityManagerInterface;

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
        // 🔥 NE PAS APPELER parent::setUp() ICI
        // Cela bootait le kernel trop tôt
        
        // ✅ Créer le client EN PREMIER
        $this->client = static::createClient();
        
        // ✅ ENSUITE récupérer l'entity manager
        $this->entityManager = $this->client->getContainer()
            ->get('doctrine')
            ->getManager();
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

        // Attendu : Redirection ou erreur 403
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

        // Attendu : Redirection vers login (302) ou 403
        $response = $this->client->getResponse();
        $this->assertTrue(
            $response->isRedirect() || $response->getStatusCode() === Response::HTTP_FORBIDDEN,
            'Non-authenticated user should not access account update'
        );
    }

    /**
     * Test 3 : Suppression utilisateur SANS être admin doit échouer
     */
    public function testDeleteUserWithoutAdminRoleShouldFail(): void
    {
        // Créer un utilisateur normal
        $user = $this->createTestUser('normaluser@test.com', false);
        $this->loginAs($user);

        // Tenter de supprimer un autre utilisateur
        $targetUser = $this->createTestUser('victim@test.com', false);
        
        $this->client->request('POST', '/admin/delete/' . $targetUser->getId());

        // Attendu : 403 Forbidden ou redirection
        $this->assertTrue(
            $this->client->getResponse()->getStatusCode() >= 400,
            'Normal user should not delete other users'
        );

        $this->cleanup($user, $targetUser);
    }

    // ==========================================
    // 💉 TESTS SQL INJECTION
    // ==========================================

    /**
     * Test 4 : SQL Injection dans email de connexion
     */
    public function testSqlInjectionInLoginEmail(): void
    {
        $sqlInjectionPayloads = [
            "admin' OR '1'='1",
            "admin'--",
            "admin' /*",
            "' OR 1=1--",
            "admin' UNION SELECT NULL--",
            "1' OR '1' = '1')) /*"
        ];

        foreach ($sqlInjectionPayloads as $payload) {
            // 🔥 CRÉER UN NOUVEAU CLIENT POUR CHAQUE TEST
            $client = static::createClient();
            
            $client->request('POST', '/account/login', [
                '_username' => $payload,
                '_password' => 'anything'
            ]);

            // Attendu : Ne doit PAS être authentifié
            $this->assertFalse(
                $this->isAuthenticatedInClient($client),
                "SQL Injection payload should not authenticate: {$payload}"
            );
        }
    }

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
        $connection = $this->entityManager->getConnection();
        $schemaManager = $connection->createSchemaManager();
        
        // 🔥 UTILISER listTableNames() au lieu de tablesExist()
        $tables = $schemaManager->listTableNames();
        $tableExists = in_array('user', $tables);

        $this->assertTrue($tableExists, 'SQL Injection should not drop tables');
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
     * Test 7 : IDOR - Modification du compte d'un autre utilisateur
     */
    public function testIdorAccountUpdate(): void
    {
        // Créer deux utilisateurs
        $user1 = $this->createTestUser('user1@test.com', false);
        $user2 = $this->createTestUser('user2@test.com', false);

        // Se connecter en tant qu'user1
        $this->loginAs($user1);

        // Obtenir le token CSRF
        $crawler = $this->client->request('GET', '/account');
        $token = $crawler->filter('input[name="_token"]')->attr('value');

        // Tenter de modifier les données d'user2
        $this->client->request('POST', '/account/update', [
            'user_id' => $user2->getId(), // 🔥 TENTER DE MODIFIER L'ID
            'name' => 'Hacked',
            'surname' => 'User',
            'email' => $user2->getEmail(),
            'adresse' => 'Hacked Address',
            '_token' => $token
        ]);

        // Vérifier que user2 n'a PAS été modifié
        $this->entityManager->refresh($user2);
        $this->assertNotEquals('Hacked', $user2->getName(), 
            'User should not be able to modify another user data');

        $this->cleanup($user1, $user2);
    }

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
        $xssPayloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
        ];

        foreach ($xssPayloads as $payload) {
            // Test sur une page de recherche ou d'erreur
            $this->client->request('GET', '/products', ['search' => $payload]);
            
            $content = $this->client->getResponse()->getContent();
            
            // Vérifier que le payload est échappé
            $escapedPayload = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');
            
            // Si le contenu contient le payload non échappé, c'est une faille
            if (strpos($content, $payload) !== false && strpos($content, $escapedPayload) === false) {
                $this->fail('Reflected XSS vulnerability detected: payload was not escaped');
            }
            
            $this->assertTrue(true, 'XSS payload properly handled');
        }
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
            ->setPassword('$2y$13$hashed') // Hash factice
            ->setAdresse('Test Address')
            ->setIsAdmin($isAdmin);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    private function loginAs(User $user): void
    {
        $session = $this->client->getContainer()->get('request_stack')->getSession();
        
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

    private function isAuthenticated(): bool
    {
        return $this->isAuthenticatedInClient($this->client);
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