# 🛡️ MemoryPC - Projet Fil Rouge Sécurité

[![Symfony](https://img.shields.io/badge/Symfony-7.3-black.svg)](https://symfony.com/)
[![PHP](https://img.shields.io/badge/PHP-8.4-blue.svg)](https://www.php.net/)
[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)](docs/SECURITY.md)

> Projet e-commerce sécurisé développé dans le cadre d'un audit de sécurité approfondi. Ce projet implémente les meilleures pratiques de sécurité web selon l'OWASP Top 10.

## 📋 Table des matières

- [À propos](#à-propos)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Sécurité](#sécurité)
- [Documentation](#documentation)
- [Licence](#licence)

## 🎯 À propos

MemoryPC est une application web e-commerce de vente de PC et composants informatiques, développée avec **Symfony 7.3** et **PHP 8.4**. Le projet a été conçu avec un accent particulier sur la sécurité, implémentant toutes les protections nécessaires contre les vulnérabilités courantes.

### Objectifs du projet

- ✅ Implémenter une application sécurisée conforme aux standards OWASP
- ✅ Démontrer les bonnes pratiques de développement sécurisé
- ✅ Fournir une base de code éducative pour l'apprentissage de la sécurité web
- ✅ Mettre en place une architecture robuste et maintenable

## ✨ Fonctionnalités

### Fonctionnalités utilisateur
- 🔐 **Authentification sécurisée** avec validation de mot de passe robuste
- 👤 **Gestion de compte** avec mise à jour des informations personnelles
- 🛒 **Panier d'achat** (fonctionnalité de base)
- 📝 **Gestion des cookies** conforme RGPD
- 🔒 **Protection CSRF** sur tous les formulaires

### Fonctionnalités administrateur
- 👥 **Gestion des utilisateurs**
- 🗑️ **Suppression d'utilisateurs** (avec vérifications de sécurité)
- 🔑 **Création d'administrateurs**
- 📊 **Dashboard d'administration**

### Sécurité implémentée
- ✅ Protection CSRF sur tous les formulaires
- ✅ Prévention des injections SQL (requêtes préparées + ORM Doctrine)
- ✅ Protection XSS (échappement automatique avec Twig)
- ✅ Prévention IDOR (vérification des permissions)
- ✅ Hachage sécurisé des mots de passe (bcrypt via Symfony)
- ✅ Validation robuste des mots de passe (12+ caractères, complexité)
- ✅ Headers de sécurité HTTP (CSP, X-Frame-Options, etc.)
- ✅ Gestion sécurisée des sessions
- ✅ Cookies sécurisés (HttpOnly, Secure, SameSite)
- ✅ HTTPS (configuration locale avec certificat auto-signé)

## 🔧 Prérequis

### Logiciels requis
- **PHP** : 8.4 ou supérieur
- **Composer** : 2.x
- **Node.js** : 18.x ou supérieur
- **NPM** : 8.x ou supérieur
- **Symfony CLI** : recommandé pour le développement
- **PostgreSQL** : 16 ou supérieur (ou SQLite pour les tests)

### Extensions PHP nécessaires
```bash
php -m | grep -E 'ctype|iconv|intl|mbstring|xml|pdo|pdo_pgsql'
```

Assurez-vous que ces extensions sont activées.

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-username/memorypc.git
cd memorypc
```

### 2. Installer les dépendances PHP

```bash
composer install
```

### 3. Installer les dépendances JavaScript

```bash
npm install
```

### 4. Configuration de l'environnement

Copiez le fichier `.env.example` vers `.env` et configurez vos paramètres :

```bash
cp .env.example .env
```

Éditez le fichier `.env` :

```env
APP_ENV=dev
APP_SECRET=VotreSecretAleatoire32Caracteres
DATABASE_URL="postgresql://user:password@127.0.0.1:5432/memorypc?serverVersion=16&charset=utf8"
```

### 5. Créer la base de données

```bash
php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate
```

### 6. Charger les données de test (optionnel)

```bash
php bin/console doctrine:fixtures:load
```

### 7. Compiler les assets

```bash
npm run build
# ou pour le développement avec watch :
npm run watch
```

### 8. Générer un certificat SSL local (HTTPS)

#### Avec Symfony CLI (recommandé)
```bash
symfony server:ca:install
symfony serve
```

#### Avec mkcert
```bash
# Installation de mkcert
brew install mkcert  # macOS
# ou
sudo apt install mkcert  # Linux

# Génération du certificat
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

### 9. Lancer le serveur

#### Avec Symfony CLI
```bash
symfony serve
```

#### Avec le serveur PHP intégré
```bash
php -S localhost:8000 -t public/
```

L'application sera accessible sur `https://localhost:8000`

## ⚙️ Configuration

### Variables d'environnement importantes

| Variable | Description | Exemple |
|----------|-------------|---------|
| `APP_ENV` | Environnement d'exécution | `dev`, `prod`, `test` |
| `APP_DEBUG` | Mode debug | `0` (prod) ou `1` (dev) |
| `APP_SECRET` | Clé secrète Symfony | Chaîne aléatoire 32+ caractères |
| `DATABASE_URL` | URL de connexion BDD | `postgresql://user:pass@host:5432/db` |
| `MAILER_DSN` | Configuration email | `smtp://localhost:1025` |

### Configuration de sécurité

Le projet utilise **Nelmio Security Bundle** pour les headers HTTP. Configuration dans `config/packages/nelmio_security.yaml`.

## 📖 Utilisation

### Créer un compte utilisateur

1. Accédez à `/account/login`
2. Cliquez sur "Créer un compte"
3. Remplissez le formulaire (le mot de passe doit contenir au minimum 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial)

### Créer un compte administrateur

Deux méthodes :

#### Via la commande Symfony (recommandé)
```bash
php bin/console app:create-admin admin@example.com MotDePasseSecure123!
```

#### Via l'interface (si vous êtes déjà admin)
1. Connectez-vous avec un compte admin
2. Accédez à `/admin`
3. Utilisez le formulaire "Créer un nouvel admin"

### Accéder à l'administration

Connectez-vous avec un compte admin, puis accédez à `/admin` ou cliquez sur "Accéder à l'administration" dans votre profil.

## 🧪 Tests

### Tests unitaires et fonctionnels

```bash
# Lancer tous les tests
php bin/phpunit

# Tests de sécurité uniquement
php bin/phpunit tests/Security/SecurityTest.php

# Test spécifique
php bin/phpunit --filter testSqlInjectionInLoginEmail
```

### Tests de sécurité automatisés

Le projet inclut **12 tests de sécurité** couvrant :
- ✅ Protection CSRF (3 tests)
- ✅ Injection SQL (3 tests)
- ✅ IDOR (3 tests)
- ✅ XSS (3 tests)

### Audit des dépendances

```bash
# Audit Composer
composer audit

# Audit NPM
npm audit
```

### Tests manuels de sécurité

Consultez le guide détaillé : [docs/MANUAL_SECURITY_TESTS.md](docs/MANUAL_SECURITY_TESTS.md)

## 🛡️ Sécurité

### Rapporter une vulnérabilité

Si vous découvrez une vulnérabilité de sécurité, **NE créez PAS d'issue publique**. 

Envoyez un email à : **security@memorypc.example** (remplacez par votre email)

### Checklist de sécurité implémentée

Consultez la checklist complète d'audit : [Checklist-Audit-Securite.md](Checklist-Audit-Securite.md)

**Score de sécurité : 95/100** ✅

### Headers de sécurité

- `Content-Security-Policy` : Politique stricte
- `X-Frame-Options: DENY` : Protection contre le clickjacking
- `X-Content-Type-Options: nosniff` : Prévention du MIME sniffing
- `Strict-Transport-Security` : Force HTTPS
- `Referrer-Policy: strict-origin-when-cross-origin`

## 📚 Documentation

### Documentation complète

- 📘 [Installation détaillée](docs/INSTALLATION.md)
- 🔐 [Guide de sécurité](docs/SECURITY.md)
- 🧪 [Guide des tests](docs/TESTING.md)
- 🏗️ [Architecture du projet](docs/ARCHITECTURE.md)
- 🔧 [Configuration avancée](docs/CONFIGURATION.md)
- 🐛 [Dépannage](docs/TROUBLESHOOTING.md)
- 📖 [API Documentation](docs/API.md)

### Structure du projet

```
memorypc/
├── assets/              # Assets frontend (JS, CSS)
├── config/              # Configuration Symfony
├── migrations/          # Migrations de base de données
├── public/              # Point d'entrée web
├── src/
│   ├── Controller/      # Contrôleurs
│   ├── Entity/          # Entités Doctrine
│   ├── Repository/      # Repositories
│   ├── Service/         # Services métier
│   └── EventListener/   # Event Listeners
├── templates/           # Templates Twig
├── tests/               # Tests automatisés
├── var/                 # Cache et logs
└── vendor/              # Dépendances Composer
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour les directives.

### Workflow de contribution

1. Fork le projet
2. Créez une branche (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📝 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus d'informations.

## 👥 Auteurs

- **Votre Nom** - *Développement initial* - [VotreGitHub](https://github.com/votre-username)

## 🙏 Remerciements

- Symfony pour le framework
- OWASP pour les guidelines de sécurité
- La communauté Symfony pour les bundles

## 📞 Support

Pour toute question ou problème :
- 📧 Email : support@memorypc.example
- 💬 Discord : [Lien vers votre Discord]
- 🐛 Issues : [GitHub Issues](https://github.com/votre-username/memorypc/issues)

---

**⚠️ Avertissement** : Ce projet est à des fins éducatives et de démonstration. Assurez-vous de personnaliser tous les aspects de sécurité (secrets, mots de passe, etc.) avant tout déploiement en production.