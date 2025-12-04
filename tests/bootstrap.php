<?php

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__).'/vendor/autoload.php';

$dotenv = new Dotenv();

// Charger .env si présent, sinon ignorer
$envFile = dirname(__DIR__).'/.env';
if (file_exists($envFile)) {
    $dotenv->bootEnv($envFile);
}

// Charger .env.test si présent
$envTestFile = dirname(__DIR__).'/.env.test';
if (file_exists($envTestFile)) {
    $dotenv->bootEnv($envTestFile);
}

// Supprimer le schema create si tu n'utilises pas de DB
// passthru('php '.dirname(__DIR__).'/bin/console doctrine:schema:create --env=test --quiet');

if (!empty($_SERVER['APP_DEBUG'])) {
    umask(0002);
}