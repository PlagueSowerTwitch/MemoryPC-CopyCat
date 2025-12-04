<?php

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__).'/vendor/autoload.php';

if (method_exists(Dotenv::class, 'bootEnv')) {
    (new Dotenv())->bootEnv(dirname(__DIR__).'/.env');
}

if (file_exists(dirname(__DIR__) . '/.env.test')) {
    (new Dotenv())->bootEnv(dirname(__DIR__) . '/.env.test');
}

passthru('php '.dirname(__DIR__).'/bin/console doctrine:schema:create --env=test --quiet');

if ($_SERVER['APP_DEBUG']) {
    umask(0002);
}
