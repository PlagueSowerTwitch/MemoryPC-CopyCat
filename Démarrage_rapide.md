# 🚀 Guide de démarrage rapide - MemoryPC

Lancez le projet en **5 minutes** !

## ⚡ Installation express

### Prérequis
- PHP 8.4+
- Composer
- Node.js 18+
- PostgreSQL 16+ (ou SQLite pour les tests)

### Étapes

```bash
# 1. Cloner et accéder au projet
git clone https://github.com/votre-username/memorypc.git
cd memorypc

# 2. Installer les dépendances
composer install
npm install

# 3. Configuration
cp .env.example .env
# Éditez .env avec vos paramètres de BDD

# 4. Base de données
php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate

# 5. Compiler les assets
npm run build

# 6. Lancer le serveur
symfony serve
# ou : php -S localhost:8000 -t public/
```

✅ **Accédez à** : `https://localhost:8000`

## 🎯 Actions de base

### Créer un compte utilisateur
1. Allez sur `/account/login`
2. Cliquez sur "Créer un compte"
3. Remplissez le formulaire
   - Mot de passe : min. 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 spécial

### Créer un compte administrateur

#### Option 1 : Via commande (si créée)
```bash
php bin/console app:create-admin admin@test.local AdminPass123!
```

#### Option 2 : Manuellement en base de données
```sql
-- Insérer un admin directement
INSERT INTO "user" (name, surname, email, password, adresse, is_admin)
VALUES (
    'Admin',
    'System',
    'admin@memorypc.local',
    '$2y$13$hashedPasswordGeneratedByBcrypt',  -- Utilisez un vrai hash bcrypt
    '123 Admin Street',
    true
);
```

Générer le hash bcrypt :
```bash
php -r "echo password_hash('AdminPass123!', PASSWORD_BCRYPT);"
```

### Accéder à l'administration
1. Connectez-vous avec un compte admin
2. Allez sur `/admin`
3. Gérez les utilisateurs

## 🧪 Lancer les tests

```bash
# Tous les tests
php bin/phpunit

# Tests de sécurité uniquement
php bin/phpunit tests/Security/SecurityTest.php

# Test spécifique
php bin/phpunit --filter testSqlInjection
```

## 🛠️ Commandes utiles

```bash
# Vider le cache
php bin/console cache:clear

# Vérifier la configuration
php bin/console debug:config

# Lister les routes
php bin/console debug:router

# Valider le schéma de BDD
php bin/console doctrine:schema:validate

# Audit de sécurité
composer audit
npm audit

# Compiler les assets en mode watch
npm run watch
```

## 📁 Structure du projet

```
memorypc/
├── assets/              # JS, CSS
│   ├── js/
│   │   ├── app.js
│   │   ├── cookie_pop-up.js
│   │   └── cookie_settings.js
│   └── styles/
│       ├── Header.css
│       ├── Home.css
│       └── ...
├── config/              # Configuration Symfony
│   ├── packages/
│   │   ├── security.yaml
│   │   ├── nelmio_security.yaml
│   │   └── ...
│   └── routes.yaml
├── src/
│   ├── Controller/
│   │   ├── AccountController.php    # Gestion des comptes
│   │   ├── AdminController.php      # Administration
│   │   └── HomeController.php
│   ├── Entity/
│   │   ├── User.php                 # Entité utilisateur
│   │   ├── Cart.php
│   │   └── Product.php
│   └── Service/
│       └── CookiePreferencesService.php
├── templates/           # Templates Twig
│   ├── account/
│   ├── admin/
│   ├── components/
│   │   ├── header.html.twig
│   │   ├── footer.html.twig
│   │   └── cookie_pop-up.html.twig
│   └── base.html.twig
├── tests/
│   └── Security/
│       └── SecurityTest.php         # 12 tests de sécurité
├── .env                 # Configuration (à ne PAS commiter)
├── .env.example         # Template de configuration
└── composer.json        # Dépendances PHP
```

## 🔑 Fonctionnalités principales

### Utilisateur
- ✅ Inscription / Connexion sécurisée
- ✅ Gestion du compte personnel
- ✅ Panier d'achat (base)
- ✅ Consentement cookies RGPD

### Administrateur
- ✅ Dashboard d'administration
- ✅ Gestion des utilisateurs
- ✅ Suppression d'utilisateurs
- ✅ Création d'autres admins

### Sécurité
- ✅ Protection CSRF
- ✅ Prévention SQL Injection
- ✅ Protection XSS
- ✅ Prévention IDOR
- ✅ Validation robuste des mots de passe
- ✅ Headers de sécurité HTTP

## 🐛 Problèmes fréquents

### Port 8000 déjà utilisé
```bash
symfony serve --port=8001
```

### Erreur "Cannot write to var/cache"
```bash
chmod -R 775 var/
```

### Base de données inaccessible
Vérifiez votre `.env` :
```env
DATABASE_URL="postgresql://user:password@127.0.0.1:5432/memorypc"
```

### Assets non compilés
```bash
npm run build
```

### Certificat SSL non reconnu
```bash
symfony server:ca:install
```

## 📚 Documentation complète

- 📘 [Installation détaillée](docs/INSTALLATION.md)
- 🛡️ [Guide de sécurité](docs/SECURITY.md)
- 🧪 [Guide des tests](docs/TESTING.md)
- 🏗️ [Architecture](docs/ARCHITECTURE.md)
- 🔧 [Configuration](docs/CONFIGURATION.md)
- 🐛 [Dépannage](docs/TROUBLESHOOTING.md)

## 🎓 Ressources pour apprendre

- [Documentation Symfony](https://symfony.com/doc/current/index.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Doctrine ORM](https://www.doctrine-project.org/projects/orm.html)
- [Twig Templates](https://twig.symfony.com/)

## 💬 Support

- 🐛 [GitHub Issues](https://github.com/votre-username/memorypc/issues)
- 📧 Email : support@memorypc.example
- 💬 Discord : [Votre serveur]

---

**🎉 Vous êtes prêt !** Commencez à explorer le projet.

**Prochaines étapes** :
1. Créez un compte utilisateur
2. Explorez l'interface
3. Créez un compte admin
4. Testez l'administration
5. Lancez les tests de sécurité
6. Lisez la documentation complète

**Bon développement ! 🚀**