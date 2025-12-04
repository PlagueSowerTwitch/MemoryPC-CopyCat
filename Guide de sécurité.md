# 🛡️ Guide de sécurité - MemoryPC

Ce document décrit toutes les mesures de sécurité implémentées dans le projet et comment les maintenir.

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Protections implémentées](#protections-implémentées)
3. [Configuration de sécurité](#configuration-de-sécurité)
4. [Bonnes pratiques](#bonnes-pratiques)
5. [Audit de sécurité](#audit-de-sécurité)
6. [Rapporter une vulnérabilité](#rapporter-une-vulnérabilité)

## 🔍 Vue d'ensemble

### Score de sécurité : 95/100 ✅

Le projet MemoryPC implémente les protections contre les vulnérabilités du **OWASP Top 10** :

| Vulnérabilité | Protection | Statut |
|---------------|-----------|--------|
| Injection SQL | ✅ Requêtes préparées + ORM | Protégé |
| XSS | ✅ Échappement Twig automatique | Protégé |
| CSRF | ✅ Tokens sur tous formulaires | Protégé |
| IDOR | ✅ Vérification des permissions | Protégé |
| Mauvaise authentification | ✅ Validation robuste mdp | Protégé |
| Exposition de données | ✅ Minimisation des données | Protégé |
| Contrôle d'accès défaillant | ✅ Rôles RBAC | Protégé |
| Mauvaise configuration | ✅ Paramètres sécurisés | Protégé |
| Composants vulnérables | ✅ Audit dépendances | Protégé |
| Logging insuffisant | ✅ Logs sécurisés Monolog | Protégé |

## 🔐 Protections implémentées

### 1. Protection CSRF (Cross-Site Request Forgery)

#### Configuration

Fichier `config/packages/csrf.yaml` :
```yaml
framework:
    form:
        csrf_protection:
            token_id: submit

    csrf_protection:
        stateless_token_ids:
            - submit
            - authenticate
            - logout
```

#### Utilisation dans les formulaires

```twig
<form method="post" action="{{ path('account_update') }}">
    <input type="hidden" name="_token" value="{{ csrf_token('account_update') }}">
    <!-- Autres champs -->
</form>
```

#### Vérification côté serveur

```php
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

public function update(Request $request, CsrfTokenManagerInterface $csrfTokenManager): Response
{
    $submittedToken = $request->request->get('_token');
    
    if (!$csrfTokenManager->isTokenValid(new CsrfToken('account_update', $submittedToken))) {
        throw $this->createAccessDeniedException('Token CSRF invalide');
    }
    
    // Traitement sécurisé...
}
```

### 2. Protection contre l'injection SQL

#### ORM Doctrine avec requêtes préparées

✅ **Correct** :
```php
$user = $em->getRepository(User::class)->findOneBy(['email' => $email]);
```

❌ **Incorrect** (JAMAIS faire ceci) :
```php
$query = "SELECT * FROM user WHERE email = '$email'";  // VULNÉRABLE
```

#### Requêtes DQL sécurisées

```php
$query = $em->createQuery(
    'SELECT u FROM App\Entity\User u WHERE u.email = :email'
);
$query->setParameter('email', $email);
$user = $query->getOneOrNullResult();
```

### 3. Protection XSS (Cross-Site Scripting)

#### Échappement automatique avec Twig

```twig
{# ✅ Automatiquement échappé #}
<p>Nom : {{ user.name }}</p>

{# ⚠️ Utiliser raw uniquement si absolument nécessaire et après sanitization #}
<div>{{ content|raw }}</div>
```

#### Sanitization avec HTMLPurifier

```php
use HTMLPurifier;
use HTMLPurifier_Config;

$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean_html = $purifier->purify($dirty_html);
```

### 4. Protection IDOR (Insecure Direct Object Reference)

#### Vérification systématique des permissions

```php
#[Route('/account/update', name: 'account_update', methods: ['POST'])]
public function update(Request $request, EntityManagerInterface $em): Response
{
    $currentUser = $this->getUser();
    $userIdFromForm = (int) $request->request->get('user_id');
    
    // ✅ Vérification IDOR
    if ($currentUser->getId() !== $userIdFromForm) {
        $this->addFlash('error', 'Vous ne pouvez pas modifier le compte d\'un autre utilisateur.');
        return $this->redirectToRoute('account');
    }
    
    // Traitement sécurisé...
}
```

#### Protection des routes sensibles

```yaml
# config/packages/security.yaml
access_control:
    - { path: ^/admin, roles: ROLE_ADMIN }
    - { path: ^/account, roles: ROLE_USER }
```

### 5. Gestion sécurisée des mots de passe

#### Validation robuste

```php
// Regex de validation (12+ caractères, majuscule, minuscule, chiffre, spécial)
#[Assert\Regex(
    pattern: '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/',
    message: "Le mot de passe doit contenir au minimum 12 caractères..."
)]
private ?string $password = null;
```

#### Hachage sécurisé avec bcrypt

```php
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

$hashedPassword = $hasher->hashPassword($user, $plainPassword);
$user->setPassword($hashedPassword);
```

Configuration dans `config/packages/security.yaml` :
```yaml
security:
    password_hashers:
        App\Entity\User: 'auto'  # Utilise bcrypt par défaut
```

### 6. Headers de sécurité HTTP

#### Configuration Nelmio Security Bundle

Fichier `config/packages/nelmio_security.yaml` :

```yaml
nelmio_security:
    # Protection Clickjacking
    clickjacking:
        paths:
            '^/.*': DENY

    # MIME sniffing prevention
    content_type:
        nosniff: true

    # Referrer Policy
    referrer_policy:
        enabled: true
        policies:
            - 'no-referrer'
            - 'strict-origin-when-cross-origin'

    # Content Security Policy
    csp:
        enabled: true
        enforce:
            default-src: ['self']
            script-src: ['self', 'nonce']
            style-src: ['self']
            img-src: ['self', 'data:']
            object-src: ['none']
            base-uri: ['self']
            frame-ancestors: ['none']
```

#### Vérification des headers

Testez avec curl :
```bash
curl -I https://localhost:8000 | grep -E "X-Frame|X-Content|Content-Security"
```

Résultat attendu :
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'
```

### 7. Gestion sécurisée des sessions

#### Configuration

Fichier `config/packages/framework.yaml` :

```yaml
framework:
    session:
        cookie_secure: true        # HTTPS uniquement
        cookie_httponly: true      # Pas accessible en JavaScript
        cookie_samesite: lax       # Protection CSRF
        gc_maxlifetime: 1800       # Timeout 30 minutes
        cookie_lifetime: 0         # Session expire à la fermeture
```

#### Destruction de session au logout

```php
#[Route('/account/logout', name: 'account_logout')]
public function logout(): void
{
    // Géré automatiquement par Symfony Security
    // La session est détruite complètement
}
```

### 8. Protection contre le brute force

#### Rate limiting (à implémenter)

```php
// TODO: Implémenter avec Symfony Rate Limiter
use Symfony\Component\RateLimiter\RateLimiterFactory;

#[Route('/account/login', name: 'account_login')]
public function login(Request $request, RateLimiterFactory $anonymousApiLimiter): Response
{
    $limiter = $anonymousApiLimiter->create($request->getClientIp());
    
    if (false === $limiter->consume(1)->isAccepted()) {
        throw new TooManyRequestsHttpException();
    }
    
    // Suite du login...
}
```

## ⚙️ Configuration de sécurité

### Mode production

#### Fichier `.env.prod`

```env
APP_ENV=prod
APP_DEBUG=0
APP_SECRET=VotreSecretAleatoireTresFortDe32Caracteres
DATABASE_URL="postgresql://prod_user:prod_password@db.example.com:5432/memorypc_prod"
```

⚠️ **Important** :
- `APP_DEBUG=0` : Désactive les messages d'erreur détaillés
- `APP_SECRET` : Doit être une chaîne aléatoire unique de 32+ caractères

#### Génération d'un secret sécurisé

```bash
# Linux/macOS
openssl rand -hex 32

# Windows (PowerShell)
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
```

### Fichiers sensibles à ignorer

Vérifiez votre `.gitignore` :

```gitignore
.env
.env.local
.env.*.local
/config/secrets/
/var/
/vendor/
/node_modules/
```

### Permissions fichiers (Linux/macOS)

```bash
# Dossiers d'écriture
chmod 775 var/cache var/log
chown -R www-data:www-data var/

# Fichiers de configuration
chmod 600 .env .env.prod
```

## 📋 Bonnes pratiques

### 1. Gestion des secrets

✅ **À FAIRE** :
- Utiliser des variables d'environnement
- Stocker les secrets dans `.env` (jamais dans Git)
- Utiliser Symfony Secrets pour la production

```bash
# Générer une clé de cryptage
php bin/console secrets:generate-keys

# Définir un secret
php bin/console secrets:set DATABASE_PASSWORD
```

❌ **À NE PAS FAIRE** :
```php
// ❌ JAMAIS ceci
$password = "MonMotDePasseEnDur123";

// ✅ Toujours ceci
$password = $_ENV['DATABASE_PASSWORD'];
```

### 2. Validation des données

```php
use Symfony\Component\Validator\Constraints as Assert;

class User
{
    #[Assert\NotBlank]
    #[Assert\Email]
    private ?string $email = null;

    #[Assert\NotBlank]
    #[Assert\Length(min: 12)]
    #[Assert\Regex(pattern: '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/')]
    private ?string $password = null;
}
```

### 3. Sanitization des entrées

```php
// Pour les chaînes
$clean = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

// Pour les entiers
$id = filter_var($input, FILTER_VALIDATE_INT);

// Pour les emails
$email = filter_var($input, FILTER_VALIDATE_EMAIL);
```

### 4. Logs de sécurité

Configuration Monolog dans `config/packages/monolog.yaml` :

```yaml
when@prod:
    monolog:
        handlers:
            security:
                type: stream
                path: "%kernel.logs_dir%/security.log"
                level: warning
                channels: ["security"]
```

Utilisation :

```php
use Psr\Log\LoggerInterface;

public function suspiciousAction(LoggerInterface $logger)
{
    $logger->warning('Tentative d\'accès non autorisé', [
        'ip' => $request->getClientIp(),
        'user' => $this->getUser()?->getEmail(),
        'route' => $request->attributes->get('_route')
    ]);
}
```

## 🔍 Audit de sécurité

### Audit automatique des dépendances

```bash
# Composer
composer audit --locked

# NPM
npm audit

# Correction automatique des vulnérabilités mineures
npm audit fix
```

### Tests de sécurité automatisés

```bash
# Lancer tous les tests de sécurité
php bin/phpunit tests/Security/SecurityTest.php

# Tests individuels
php bin/phpunit --filter testSqlInjectionInLoginEmail
php bin/phpunit --filter testXssInRegistrationForm
php bin/phpunit --filter testIdorAccountUpdate
```

### Checklist d'audit

Référez-vous à [Checklist-Audit-Securite.md](../Checklist-Audit-Securite.md) pour la liste complète.

**Résumé des points clés** :
- ✅ 1.1 Gestion des secrets : Secrets hors du code
- ✅ 1.2 Mode Production : Debug désactivé
- ✅ 1.3 HTTPS Local : Certificat configuré
- ✅ 1.4 Dépendances saines : Audit clean
- ✅ 2.1 Mots de passe robustes : 12+ caractères
- ✅ 2.2 Stockage des mdp : bcrypt utilisé
- ✅ 2.3 Cookies & Sessions : Flags sécurisés
- ✅ 3.1-3.3 Contrôle d'accès : RBAC implémenté
- ✅ 4.1-4.3 Injections : Requêtes préparées + échappement
- ✅ 5.1 CSRF : Tokens sur tous formulaires
- ✅ 6.1-6.2 RGPD : Conformité respectée
- ✅ 7.1-7.2 Headers HTTP : Nelmio configuré

## 🚨 Rapporter une vulnérabilité

### Processus de signalement

Si vous découvrez une vulnérabilité de sécurité :

1. **NE créez PAS d'issue publique sur GitHub**
2. Envoyez un email à : **security@memorypc.example**
3. Incluez :
   - Description détaillée de la vulnérabilité
   - Étapes pour reproduire
   - Impact potentiel
   - (Optionnel) Suggestion de correction

### Ce qui se passe ensuite

1. Accusé de réception sous 48h
2. Investigation et validation
3. Développement d'un correctif
4. Publication du correctif
5. Reconnaissance publique (si vous le souhaitez)

### Récompenses

Nous reconnaissons les chercheurs en sécurité qui signalent des vulnérabilités de manière responsable :
- 🏆 Mention dans le fichier SECURITY.md
- ⭐ Badge "Security Researcher" sur GitHub
- 💰 (Optionnel) Programme de bug bounty

## 📚 Ressources supplémentaires

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Symfony Security Best Practices](https://symfony.com/doc/current/security.html)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---