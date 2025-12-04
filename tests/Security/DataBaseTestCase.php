<?php

namespace App\Tests;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Common\DataFixtures\Purger\ORMPurger;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class DatabaseTestCase extends WebTestCase
{
    protected ?EntityManagerInterface $entityManager = null;
    protected $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();

        /** @var EntityManagerInterface $em */
        $em = static::getContainer()->get(EntityManagerInterface::class);
        $this->entityManager = $em;

        // 🔥 Purge TRUNCATE — indispensable pour éviter les doublons email
        $purger = new ORMPurger($this->entityManager);
        $purger->setPurgeMode(ORMPurger::PURGE_MODE_TRUNCATE);
        $purger->purge();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        if ($this->entityManager) {
            $this->entityManager->close();
        }

        $this->entityManager = null;
    }
}