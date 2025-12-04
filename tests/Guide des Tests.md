# 🧪 Guide des tests - MemoryPC

Ce guide explique en détail comment exécuter, comprendre et étendre les tests du projet.

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Installation et configuration](#installation-et-configuration)
3. [Tests automatisés](#tests-automatisés)
4. [Tests de sécurité](#tests-de-sécurité)
5. [Tests manuels](#tests-manuels)
6. [Écrire de nouveaux tests](#écrire-de-nouveaux-tests)
7. [Couverture de code](#couverture-de-code)
8. [Intégration continue](#intégration-continue)
9. [Dépannage](#dépannage)

## 🔍 Vue d'ensemble

### Types de tests implémentés

Le projet MemoryPC contient **12 tests de sécurité automatisés** couvrant :

| Type de test | Nombre | Fichier | Description |
|--------------|--------|---------|-------------|
| **CSRF** | 3 tests | `SecurityTest.php` | Protection formulaires |
| **SQL Injection** | 3 tests | `SecurityTest.php` | Injection de requêtes |
| **IDOR** | 3 tests | `SecurityTest.php` | Contrôle d'accès |
| **XSS** | 3 tests | `SecurityTest.php` | Cross-Site Scripting |

### Framework de tests

- **PHPUnit 12.4** : Framework de tests unitaires et fonctionnels
- **Symfony WebTestCase** : Tests d'intégration web
- **Doctrine DataFixtures** : Gestion des données de test
- **SQLite in-memory** : Base de données de test rapide

## ⚙️ Installation et configuration

### 1. Vérifier PHPUnit

```bash
# Vérifier que PHPUnit est installé
php bin/phpunit --version

# Résultat attendu :
# PHPUnit 12.4.x by Sebastian Bergmann
```

Si PHPUnit n'est pas installé :
```bash
composer require --dev phpunit/phpunit
```

### 2. Configuration de l'environnement de test

Le fichier `.env.test` est automatiquement chargé lors des tests :

```env
# .env.test
KERNEL_CLASS='App\Kernel'
APP_SECRET='$ecretf0rt3st'
APP_ENV=test
APP_DEBUG=1
DATABASE_URL="sqlite:///:memory:"
MESSENGER_TRANSPORT_DSN=doctrine://default?auto_setup=0
DEFAULT_URI="http://localhost:8000"
```

### 3. Configuration PHPUnit

Le fichier `phpunit.dist.xml` contient la configuration :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="tests/bootstrap.php"
         colors="true"
         failOnDeprecation="true"
         failOnNotice="true"
         failOnWarning="true">

    <php>
        <ini name="display_errors" value="1"/>
        <ini name="error_reporting" value="-1"/>
        <server name="APP_ENV" value="test" force="true"/>
        <server name="APP_DEBUG" value="1" force="true"/>
        <env name="DATABASE_URL" value="sqlite:///%kernel.project_dir%/var/data_test.db"/>
        <server name="SHELL_VERBOSITY" value="-1"/>
    </php>

    <testsuites>
        <testsuite name="Application Test Suite">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

### 4. Initialisation de la base de données de test

La base de données SQLite est automatiquement créée en mémoire pour chaque exécution de tests, garantissant :
- ✅ Isolation complète entre les tests
- ✅ Rapidité d'exécution
- ✅ Pas de pollution des données

## 🤖 Tests automatisés

### Lancer tous les tests

```bash
# Tous les tests
php bin/phpunit

# Avec plus de détails
php bin/phpunit --verbose

# Avec couleurs (si non activé par défaut)
php bin/phpunit --colors=always
```

**Résultat attendu** :
```
PHPUnit 12.4.x by Sebastian Bergmann

.............                                                     12 / 12 (100%)

Time: 00:02.450, Memory: 28.00 MB

OK (12 tests, 24 assertions)
```

### Lancer une suite de tests spécifique

```bash
# Tests de sécurité uniquement
php bin/phpunit tests/Security/

# Avec le chemin complet
php bin/phpunit tests/Security/SecurityTest.php
```

### Lancer un test individuel

```bash
# Par nom de méthode
php bin/phpunit --filter testSqlInjectionInLoginEmail

# Par pattern
php bin/phpunit --filter 'test.*Injection'

# Afficher le nom des tests
php bin/phpunit --testdox
```

**Résultat avec --testdox** :
```
Security (App\Tests\Security\SecurityTest)
 ✔ Register without csrf token should fail
 ✔ Update account without auth should fail
 ✔ Delete user without admin role should fail
 ✔ Sql injection in login email
 ✔ Sql injection in registration
 ✔ Sql injection in search
 ✔ Idor account update
 ✔ Idor profile access
 ✔ Idor user deletion
 ✔ Xss in registration form
 ✔ Stored xss
 ✔ Reflected xss
```

## 🛡️ Tests de sécurité détaillés

### Structure des tests de sécurité

Le fichier `tests/Security/SecurityTest.php` contient 12 tests organisés en 4 catégories :

```
SecurityTest.php
├── CSRF (3 tests)
│   ├── testRegisterWithoutCsrfTokenShouldFail()
│   ├── testUpdateAccountWithoutAuthShouldFail()
│   └── testDeleteUserWithoutAdminRoleShouldFail()
├── SQL Injection (3 tests)
│   ├── testSqlInjectionInLoginEmail()
│   ├── testSqlInjectionInRegistration()
│   └── testSqlInjectionInSearch()
├── IDOR (3 tests)
│   ├── testIdorAccountUpdate()
│   ├── testIdorProfileAccess()
│   └── testIdorUserDeletion()
└── XSS (3 tests)
    ├── testXssInRegistrationForm()
    ├── testStoredXss()
    └── testReflectedXss()
```

### 1. Tests CSRF (Cross-Site Request Forgery)

#### Test 1 : Inscription sans token CSRF

```bash
php bin/phpunit --filter testRegisterWithoutCsrfTokenShouldFail
```

**Ce que teste ce test :**
- Tente de créer un compte sans fournir de token CSRF
- Vérifie que la requête est rejetée (code HTTP ≠ 200)

**Code simplifié :**
```php
public function testRegisterWithoutCsrfTokenShouldFail(): void
{
    // Envoie une requête POST sans token CSRF
    $this->client->request('POST', '/account/register', [
        'name' => 'TestUser',
        'email' => 'test@example.com',
        'password' => 'SecurePass123!',
        // PAS de token CSRF
    ]);

    // Vérifie que la requête échoue
    $this->assertNotEquals(Response::HTTP_OK, 
        $this->client->getResponse()->getStatusCode());
}
```

**Résultat attendu :** ✅ PASS - La requête est rejetée

#### Test 2 : Mise à jour sans authentification

```bash
php bin/phpunit --filter testUpdateAccountWithoutAuthShouldFail
```

**Ce que teste ce test :**
- Tente de modifier un compte sans être connecté
- Vérifie une redirection ou un code 403

#### Test 3 : Suppression sans privilèges admin

```bash
php bin/phpunit --filter testDeleteUserWithoutAdminRoleShouldFail
```

**Ce que teste ce test :**
- Un utilisateur normal tente de supprimer un autre utilisateur
- Vérifie que l'action est bloquée (403 ou redirection)

### 2. Tests SQL Injection

#### Test 4 : SQL Injection dans le login

```bash
php bin/phpunit --filter testSqlInjectionInLoginEmail
```

**Ce que teste ce test :**
- Teste plusieurs payloads SQL classiques :
  - `admin' OR '1'='1`
  - `admin'--`
  - `' OR 1=1--`
- Vérifie qu'aucun ne permet de se connecter

**Payloads testés :**
```php
$sqlPayloads = [
    "admin' OR '1'='1",
    "admin'--",
    "' OR 1=1--",
    "admin' UNION SELECT NULL--",
];
```

**Résultat attendu :** ✅ PASS - Aucune connexion réussie

#### Test 5 : SQL Injection dans l'inscription

```bash
php bin/phpunit --filter testSqlInjectionInRegistration
```

**Ce que teste ce test :**
- Tente d'injecter `test'; DROP TABLE user; --`
- Vérifie que la table `user` existe toujours après

**Code de vérification :**
```php
// Vérifie que la table existe toujours
$schema = $this->entityManager->getConnection()->createSchemaManager();
$tables = $schema->listTableNames();

$this->assertContains('user', $tables, 
    'User table must not be dropped.');
```

#### Test 6 : SQL Injection dans la recherche

```bash
php bin/phpunit --filter testSqlInjectionInSearch
```

**Ce que teste ce test :**
- Teste l'injection dans les paramètres de recherche
- Vérifie l'absence d'erreur 500 (Internal Server Error)

### 3. Tests IDOR (Insecure Direct Object Reference)

#### Test 7 : Modification du compte d'autrui

```bash
php bin/phpunit --filter testIdorAccountUpdate
```

**Scénario du test :**
1. Crée 2 utilisateurs (user1 et user2)
2. Se connecte en tant que user1
3. Tente de modifier user2 en changeant l'ID dans la requête
4. Vérifie que user2 n'a PAS été modifié

**Code clé :**
```php
// Tente de modifier user2 avec la session de user1
$this->client->request('POST', '/account/update', [
    'user_id' => $user2->getId(),  // ID différent !
    'name' => 'Hacked',
    // ...
]);

// Vérifie que user2 n'a pas changé
$this->entityManager->refresh($user2);
$this->assertNotEquals('Hacked', $user2->getName());
```

**Résultat attendu :** ✅ PASS - user2 reste inchangé

#### Test 8 : Accès au profil d'autrui

```bash
php bin/phpunit --filter testIdorProfileAccess
```

**Ce que teste ce test :**
- Se connecte en tant que user1
- Vérifie qu'on voit uniquement ses propres données
- S'assure qu'on ne peut pas accéder aux données de user2

#### Test 9 : Suppression d'utilisateur

```bash
php bin/phpunit --filter testIdorUserDeletion
```

**Scénario en 2 parties :**

**Partie 1 - Admin peut supprimer :**
```php
$admin = $this->createTestUser('admin@test.com', true);
$victim = $this->createTestUser('victim@test.com', false);

$this->loginAs($admin);
$this->client->request('POST', '/admin/delete/' . $victim->getId());

// Vérifie que victim est supprimé
$this->assertNull(
    $this->entityManager->find(User::class, $victim->getId())
);
```

**Partie 2 - Utilisateur normal ne peut PAS supprimer :**
```php
$normalUser = $this->createTestUser('normal@test.com', false);
$anotherVictim = $this->createTestUser('victim2@test.com', false);

$this->loginAs($normalUser);
$this->client->request('POST', '/admin/delete/' . $anotherVictim->getId());

// Vérifie que anotherVictim existe toujours
$this->assertNotNull(
    $this->entityManager->find(User::class, $anotherVictim->getId())
);
```

**Résultat attendu :** ✅ PASS - Contrôle d'accès respecté

### 4. Tests XSS (Cross-Site Scripting)

#### Test 10 : XSS dans l'inscription

```bash
php bin/phpunit --filter testXssInRegistrationForm
```

**Payloads testés :**
```php
$xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
];
```

**Vérification :**
```php
// Récupère le contenu de la page
$content = $this->client->getResponse()->getContent();

// Vérifie que le script n'est PAS exécutable
$this->assertStringNotContainsString(
    '<script>alert',
    $content,
    'XSS payload should be escaped'
);
```

**Résultat attendu :** ✅ PASS - Le script est échappé

#### Test 11 : XSS Stored (persistant)

```bash
php bin/phpunit --filter testStoredXss
```

**Scénario :**
1. Créer un utilisateur avec un payload XSS dans l'adresse
2. Se connecter et afficher le profil
3. Vérifier que le payload est échappé dans le HTML

**Payload :**
```javascript
<script>document.cookie="hacked=true";</script>
```

#### Test 12 : XSS Reflected (réfléchi)

```bash
php bin/phpunit --filter testReflectedXss
```

**Ce que teste ce test :**
- Injecte un payload dans les paramètres URL
- Vérifie qu'il est échappé dans la réponse

## 🧪 Tests manuels complémentaires

### 1. Test CSRF avec Burp Suite

**Outil nécessaire :** [Burp Suite Community](https://portswigger.net/burp/communitydownload)

**Procédure :**

1. **Démarrer Burp Suite**
```bash
java -jar burpsuite.jar
```

2. **Configurer le proxy du navigateur**
   - Proxy : `127.0.0.1:8080`
   - Activer l'interception dans Burp

3. **Capturer une requête POST**
   - Allez sur `/account/login`
   - Soumettez le formulaire
   - Burp intercepte la requête

4. **Supprimer le token CSRF**
   - Supprimez la ligne `_csrf_token=...`
   - Cliquez sur "Forward"

5. **Vérifier le résultat**
   - ✅ **ATTENDU** : Erreur 403 ou message "Token invalide"
   - ❌ **CRITIQUE** : Connexion réussie → FAILLE CSRF

### 2. Test SQL Injection avec SQLMap

**Outil nécessaire :** [SQLMap](https://sqlmap.org/)

```bash
# Installation
sudo apt install sqlmap

# Test sur le login
sqlmap -u "http://localhost:8000/account/login" \
  --data="username=test&password=test" \
  --level=5 --risk=3 \
  --batch

# Test sur la recherche (si implémentée)
sqlmap -u "http://localhost:8000/products?search=*" \
  --level=3 --risk=2
```

**Résultat attendu :** 
```
[*] testing connection to the target URL
[*] heuristic (basic) test shows that GET parameter 'search' might not be injectable
[*] testing for SQL injection on GET parameter 'search'
[*] GET parameter 'search' does not seem to be injectable
```

### 3. Test XSS avec navigateur

**Payloads à tester manuellement :**

```html
<!-- Test 1 : Script simple -->
<script>alert(1)</script>

<!-- Test 2 : Event handler -->
<img src=x onerror=alert(1)>

<!-- Test 3 : SVG -->
<svg/onload=alert(1)>

<!-- Test 4 : Iframes -->
<iframe src="javascript:alert(1)">

<!-- Test 5 : Attribut style -->
<div style="background:url(javascript:alert(1))">
```

**Procédure :**
1. Créer un compte avec le payload dans le nom
2. Se reconnecter
3. Aller sur `/account`
4. Inspecter le code source HTML
5. Vérifier que le payload est échappé :

```html
<!-- ✅ SÉCURISÉ -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- ❌ VULNÉRABLE -->
<script>alert(1)</script>
```

### 4. Test IDOR manuel

**Test de manipulation d'ID :**

1. **Se connecter avec user ID=5**
2. **Capturer la requête de mise à jour** (Burp Suite ou DevTools)
3. **Modifier le user_id dans le POST** :

```http
POST /account/update HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded

user_id=10&name=Hacked&email=victim@test.com&_token=abc123
```

4. **Envoyer la requête**
5. **Vérifier** :
   - ✅ **ATTENDU** : 403 Forbidden ou message d'erreur
   - ❌ **CRITIQUE** : Modification réussie → FAILLE IDOR

## 🔧 Écrire de nouveaux tests

### Structure de base d'un test

```php
<?php

namespace App\Tests\Security;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class MySecurityTest extends WebTestCase
{
    private $client;
    private $entityManager;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->entityManager = $this->client->getContainer()
            ->get('doctrine')
            ->getManager();
    }

    public function testMySecurityFeature(): void
    {
        // Arrange : Préparer les données
        $user = $this->createTestUser('test@example.com');

        // Act : Exécuter l'action à tester
        $this->client->request('POST', '/some-route', [
            'data' => 'value'
        ]);

        // Assert : Vérifier le résultat
        $this->assertEquals(200, 
            $this->client->getResponse()->getStatusCode()
        );
    }

    private function createTestUser(string $email): User
    {
        $user = new User();
        $user->setEmail($email);
        $user->setPassword(password_hash('test', PASSWORD_BCRYPT));
        // ...

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
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
```

### Exemple : Tester une nouvelle fonctionnalité

**Scénario :** Tester l'ajout de produit au panier

```php
public function testAddToCartRequiresAuthentication(): void
{
    // Tente d'ajouter un produit sans être connecté
    $this->client->request('POST', '/cart/add/1');
    
    $response = $this->client->getResponse();
    
    // Vérifie la redirection vers login
    $this->assertTrue(
        $response->isRedirect() || 
        $response->getStatusCode() === 403
    );
}

public function testUserCannotAddToOtherUserCart(): void
{
    // Créer 2 utilisateurs avec leurs paniers
    $user1 = $this->createTestUser('user1@test.com');
    $user2 = $this->createTestUser('user2@test.com');
    
    // Se connecter en tant que user1
    $this->loginAs($user1);
    
    // Tenter d'ajouter au panier de user2
    $this->client->request('POST', '/cart/add/1', [
        'cart_id' => $user2->getCart()->getId()
    ]);
    
    // Vérifier que ça échoue
    $this->assertEquals(403, 
        $this->client->getResponse()->getStatusCode()
    );
}
```

### Helper pour se connecter

```php
private function loginAs(User $user): void
{
    $this->client->request('GET', '/');
    
    $session = $this->client->getRequest()->getSession();
    $firewallName = 'main';
    
    $token = new UsernamePasswordToken(
        $user,
        $firewallName,
        $user->getRoles()
    );
    
    $session->set('_security_' . $firewallName, serialize($token));
    $session->save();
    
    $cookie = new Cookie($session->getName(), $session->getId());
    $this->client->getCookieJar()->set($cookie);
}
```

## 📊 Couverture de code

### Générer un rapport de couverture

```bash
# Générer la couverture HTML
XDEBUG_MODE=coverage php bin/phpunit --coverage-html var/coverage

# Ouvrir le rapport
open var/coverage/index.html  # macOS
xdg-open var/coverage/index.html  # Linux
start var/coverage/index.html  # Windows
```

### Couverture par ligne de commande

```bash
# Couverture texte
php bin/phpunit --coverage-text

# Couverture avec seuil minimum
php bin/phpunit --coverage-text --coverage-clover=coverage.xml
```

**Exemple de résultat :**
```
Code Coverage Report:
  2024-12-04 10:30:45

 Summary:
  Classes: 85.71% (12/14)
  Methods: 78.26% (36/46)
  Lines:   82.50% (165/200)

\App\Controller:
  AccountController
    Methods:  87.50% ( 7/ 8)
    Lines:    90.00% (45/50)
```

### Objectifs de couverture

Pour ce projet :
- ✅ **Contrôleurs de sécurité** : 90%+ couverture
- ✅ **Entités** : 80%+ couverture
- ✅ **Services** : 85%+ couverture

## 🔄 Intégration continue (CI/CD)

### Configuration GitHub Actions

Le fichier `.github/workflows/ci.yaml` exécute automatiquement :

```yaml
name: Dependency Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: 8.4
          
      - name: Install dependencies
        run: composer install --no-scripts
        
      - name: Composer Security Audit
        run: composer audit --locked
        
      - name: NPM Audit
        run: npm audit --audit-level=high
```

### Ajouter l'exécution des tests

Ajoutez ces étapes au workflow :

```yaml
      - name: Run PHPUnit tests
        run: php bin/phpunit
        
      - name: Generate coverage
        run: XDEBUG_MODE=coverage php bin/phpunit --coverage-clover=coverage.xml
        
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

## 🐛 Dépannage

### Problème : "Class 'PHPUnit\Framework\TestCase' not found"

**Solution :**
```bash
composer require --dev phpunit/phpunit
```

### Problème : "Cannot write to database in test"

**Solution :**
Vérifiez le fichier `.env.test` :
```env
DATABASE_URL="sqlite:///:memory:"
```

### Problème : "Table user doesn't exist"

**Solution :**
```bash
# Mode test avec SQLite
APP_ENV=test php bin/console doctrine:schema:create
```

### Problème : Tests lents

**Optimisations :**

1. **Utiliser SQLite en mémoire** (déjà configuré)
2. **Réduire les fixtures**
3. **Paralléliser les tests** :

```bash
composer require --dev brianium/paratest

vendor/bin/paratest --processes 4
```

### Problème : "Token CSRF manquant" dans les tests

**Solution :**
```php
// Récupérer le token depuis la page
$crawler = $this->client->request('GET', '/account');
$token = $crawler->filter('input[name="_token"]')->attr('value');

// Utiliser le token dans la requête
$this->client->request('POST', '/account/update', [
    '_token' => $token,
    // ...
]);
```

### Problème : Tests qui échouent aléatoirement

**Causes possibles :**
1. **Isolation insuffisante** : Vérifiez le `tearDown()`
2. **Dépendances entre tests** : Chaque test doit être indépendant
3. **Problème de timing** : Ajoutez des attentes si nécessaire

**Solution :**
```php
protected function setUp(): void
{
    parent::setUp();
    
    // Purge complète de la DB
    $purger = new ORMPurger($this->entityManager);
    $purger->setPurgeMode(ORMPurger::PURGE_MODE_TRUNCATE);
    $purger->purge();
}
```

## 📚 Ressources supplémentaires

### Documentation officielle
- [PHPUnit Documentation](https://docs.phpunit.de/)
- [Symfony Testing](https://symfony.com/doc/current/testing.html)
- [Doctrine Testing](https://www.doctrine-project.org/projects/doctrine-orm/en/latest/reference/testing.html)

### Tutoriels
- [Testing Symfony Applications](https://symfony.com/doc/current/testing.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PHP Security Testing](https://phpsecurity.readthedocs.io/)

### Outils recommandés
- [Burp Suite](https://portswigger.net/burp) - Tests de sécurité
- [OWASP ZAP](https://www.zaproxy.org/) - Scan de vulnérabilités
- [SQLMap](https://sqlmap.org/) - Test d'injection SQL
- [Codecov](https://codecov.io/) - Couverture de code

## 📞 Support

Si vous rencontrez des problèmes avec les tests :

1. Consultez la section [Dépannage](#dépannage)
2. Vérifiez les [Issues GitHub](https://github.com/votre-username/memorypc/issues)
3. Contactez : testing@memorypc.example

---

**Dernière mise à jour** : Décembre 2025

**Prochaines améliorations prévues** :
- [ ] Tests end-to-end avec Panther
- [ ] Tests de performance avec Apache Bench
- [ ] Tests de charge avec Locust
- [ ] Mutation testing avec Infection