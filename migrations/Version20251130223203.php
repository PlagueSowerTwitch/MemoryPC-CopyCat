<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20251130223203 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE cart DROP CONSTRAINT fk_ba388b742d8d3b5');
        $this->addSql('ALTER TABLE cart ADD CONSTRAINT FK_BA388B742D8D3B5 FOREIGN KEY (user_cart_id) REFERENCES "user" (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE "user" ALTER password TYPE VARCHAR(255)');
        $this->addSql('ALTER TABLE "user" ALTER is_admin SET DEFAULT false');
        $this->addSql('ALTER TABLE "user" RENAME COLUMN mail TO email');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649E7927C74 ON "user" (email)');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE cart DROP CONSTRAINT FK_BA388B742D8D3B5');
        $this->addSql('ALTER TABLE cart ADD CONSTRAINT fk_ba388b742d8d3b5 FOREIGN KEY (user_cart_id) REFERENCES "user" (id) NOT DEFERRABLE INITIALLY IMMEDIATE');
        $this->addSql('DROP INDEX UNIQ_8D93D649E7927C74');
        $this->addSql('ALTER TABLE "user" ALTER password TYPE VARCHAR(50)');
        $this->addSql('ALTER TABLE "user" ALTER is_admin DROP DEFAULT');
        $this->addSql('ALTER TABLE "user" RENAME COLUMN email TO mail');
    }
}
