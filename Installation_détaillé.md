# 📘 Guide d'installation détaillé - MemoryPC

Ce guide vous accompagne pas à pas dans l'installation complète du projet MemoryPC.

## Table des matières

1. [Prérequis système](#prérequis-système)
2. [Installation des dépendances](#installation-des-dépendances)
3. [Configuration de la base de données](#configuration-de-la-base-de-données)
4. [Configuration HTTPS](#configuration-https)
5. [Compilation des assets](#compilation-des-assets)
6. [Vérification de l'installation](#vérification-de-linstallation)
7. [Problèmes courants](#problèmes-courants)

## 🔧 Prérequis système

### Windows

#### Installation de PHP 8.4

1. Téléchargez PHP 8.4 depuis [windows.php.net](https://windows.php.net/download/)
2. Choisissez la version **Thread Safe** (x64)
3. Extrayez l'archive dans `C:\php`
4. Ajoutez `C:\php` au PATH système
5. Copiez `php.ini-development` vers `php.ini`
6. Activez les extensions nécessaires dans `php.ini` :

```ini
extension=ctype
extension=curl
extension=fileinfo
extension=intl
extension=mbstring
extension=openssl
extension=pdo_pgsql
extension=pgsql
extension=tokenizer
extension=xml
```

#### Installation de Composer

```powershell
# Via l'installateur officiel
Invoke-WebRequest -Uri https://getcomposer.org/Composer-Setup.exe -OutFile composer-setup.exe
.\composer-setup.exe
```

#### Installation de Node.js

Téléchargez et installez depuis [nodejs.org](https://nodejs.org/) (version LTS recommandée)

#### Installation de PostgreSQL

1. Téléchargez depuis [postgresql.org](https://www.postgresql.org/download/windows/)
2. Installez avec le port par défaut (5432)
3. Notez le mot de passe postgres

### macOS

```bash
# Installation via Homebrew
brew install php@8.4
brew install composer
brew install node
brew install postgresql@16

# Démarrer PostgreSQL
brew services start postgresql@16
```

### Linux (Ubuntu/Debian)

```bash
# Ajout du repository PHP 8.4
sudo add-apt-repository ppa:ondrej/php
sudo apt update

# Installation des paquets
sudo apt install php8.4 php8.4-cli php8.4-common php8.4-curl \
    php8.4-mbstring php8.4-xml php8.4-intl php8.4-pgsql \
    php8.4-gd php8.4-zip

# Installation de Composer
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer

# Installation de Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs

# Installation de PostgreSQL
sudo apt install postgresql-16 postgresql-contrib
```

## 📦 Installation des dépendances

### 1. Cloner le projet

```bash
git clone https://github.com/votre-username/memorypc.git
cd memorypc
```

### 2. Installer les dépendances PHP

```bash
composer install --no-scripts
```

Si vous rencontrez des erreurs de mémoire :

```bash
COMPOSER_MEMORY_LIMIT=-1 composer install --no-scripts
```

### 3. Installer les dépendances JavaScript

```bash
npm install
```

En cas d'erreur, essayez :

```bash
npm install --legacy-peer-deps
```

## 🗄️ Configuration de la base de données

### PostgreSQL (Production/Développement)

#### 1. Créer un utilisateur PostgreSQL

```bash
# Linux/macOS
sudo -u postgres createuser --createdb --pwprompt memorypc_user

# Windows (via psql)
psql -U postgres
CREATE USER memorypc_user WITH PASSWORD 'votre_mot_de_passe';
ALTER USER memorypc_user CREATEDB;
\q
```

#### 2. Configurer le fichier .env

```env
DATABASE_URL="postgresql://memorypc_user:votre_mot_de_passe@127.0.0.1:5432/memorypc?serverVersion=16&charset=utf8"
```

#### 3. Créer la base de données

```bash
php bin/console doctrine:database:create
```

#### 4. Exécuter les migrations

```bash
php bin/console doctrine:migrations:migrate
```

### SQLite (Tests uniquement)

Pour les tests, SQLite est utilisé automatiquement via `.env.test` :

```env
DATABASE_URL="sqlite:///%kernel.project_dir%/var/data_test.db"
```

## 🔒 Configuration HTTPS

### Méthode 1 : Symfony CLI (recommandée)

```bash
# Installation de Symfony CLI
# Windows
scoop install symfony-cli

# macOS
brew install symfony-cli

# Linux
curl -sS https://get.symfony.com/cli/installer | bash

# Installer le certificat CA local
symfony server:ca:install

# Démarrer le serveur HTTPS
symfony serve
```

Le serveur sera accessible sur `https://127.0.0.1:8000`

### Méthode 2 : mkcert

```bash
# Installation
# macOS
brew install mkcert

# Linux
sudo apt install libnss3-tools
wget -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64
chmod +x mkcert
sudo mv mkcert /usr/local/bin/

# Windows
choco install mkcert

# Génération des certificats
mkcert -install
mkcert localhost 127.0.0.1 ::1

# Résultat : localhost.pem et localhost-key.pem
```

#### Configuration Apache (si utilisé)

```apache
<VirtualHost *:443>
    ServerName localhost
    DocumentRoot /path/to/memorypc/public

    SSLEngine on
    SSLCertificateFile /path/to/localhost.pem
    SSLCertificateKeyFile /path/to/localhost-key.pem

    <Directory /path/to/memorypc/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## 🎨 Compilation des assets

### Mode développement (avec watch)

```bash
npm run watch
```

Laissez cette commande tourner dans un terminal séparé pendant le développement.

### Mode production

```bash
npm run build
```

### Vérifier la configuration Webpack Encore

```bash
npx encore --version
```

## ✅ Vérification de l'installation

### 1. Vérifier PHP et les extensions

```bash
php -v
php -m
```

Vérifiez que les extensions suivantes sont présentes :
- ctype, curl, fileinfo, intl, mbstring, openssl, pdo_pgsql, tokenizer, xml

### 2. Vérifier Composer

```bash
composer --version
```

### 3. Vérifier Node et NPM

```bash
node -v
npm -v
```

### 4. Vérifier la base de données

```bash
php bin/console doctrine:schema:validate
```

Résultat attendu :
```
[OK] The mapping files are correct.
[OK] The database schema is in sync with the mapping files.
```

### 5. Vérifier les assets compilés

```bash
ls -la public/build/
```

Vous devriez voir des fichiers JS et CSS compilés.

### 6. Test de connexion

1. Démarrez le serveur :
```bash
symfony serve
# ou
php -S localhost:8000 -t public/
```

2. Accédez à `https://localhost:8000`
3. Vous devriez voir la page d'accueil

### 7. Créer un compte de test

```bash
# Via la console Symfony (si commande personnalisée créée)
php bin/console app:create-admin admin@test.local AdminPass123!

# Ou via l'interface web
# Allez sur /account/login et créez un compte
```

### 8. Lancer les tests

```bash
php bin/phpunit
```

Tous les tests doivent passer (✔).

## 🐛 Problèmes courants

### Erreur : "Doctrine migrations have been executed in the database"

```bash
# Réinitialiser la base de données
php bin/console doctrine:database:drop --force
php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate
```

### Erreur : "PHP extension pdo_pgsql is not installed"

```bash
# Ubuntu/Debian
sudo apt install php8.4-pgsql

# macOS
brew install php@8.4-pgsql

# Windows
# Décommentez dans php.ini :
extension=pdo_pgsql
extension=pgsql
```

### Erreur : "Webpack Encore not found"

```bash
npm install --save-dev @symfony/webpack-encore
```

### Erreur : "Access denied for user"

Vérifiez vos identifiants dans `.env` :
```env
DATABASE_URL="postgresql://user:password@127.0.0.1:5432/memorypc?serverVersion=16"
```

### Certificat SSL non reconnu

```bash
# Réinstaller le CA local
symfony server:ca:uninstall
symfony server:ca:install

# Ou avec mkcert
mkcert -uninstall
mkcert -install
```

### Port 8000 déjà utilisé

```bash
# Changer le port
symfony serve --port=8001

# Ou avec PHP
php -S localhost:8001 -t public/
```

### Erreur "Cannot write to var/cache"

```bash
# Linux/macOS
sudo chown -R $USER:$USER var/
chmod -R 775 var/

# Windows (exécuter en tant qu'administrateur)
icacls var /grant Users:F /t
```

## 🚀 Étapes suivantes

Une fois l'installation terminée :

1. ✅ Consultez le [Guide de sécurité](SECURITY.md)
2. ✅ Lisez la [Documentation de l'architecture](ARCHITECTURE.md)
3. ✅ Explorez les [Tests de sécurité](../tests/Test_Manuels_securité.md)
4. ✅ Configurez votre IDE (voir [CONFIGURATION.md](CONFIGURATION.md))

## 📞 Besoin d'aide ?

- 📖 Consultez le [Guide de dépannage](TROUBLESHOOTING.md)
- 💬 Posez une question sur GitHub Issues
- 📧 Contactez : support@memorypc.example

---

**Dernière mise à jour** : Décembre 2025