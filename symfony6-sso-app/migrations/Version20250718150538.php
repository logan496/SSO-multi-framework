<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20250718150538 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, email VARCHAR(180) NOT NULL, roles CLOB NOT NULL --(DC2Type:json)
        , password VARCHAR(255) DEFAULT NULL, name VARCHAR(255) NOT NULL, keycloak_id VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL --(DC2Type:datetime_immutable)
        , updated_at DATETIME NOT NULL --(DC2Type:datetime_immutable)
        )');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649E7927C74 ON user (email)');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649491914B1 ON user (keycloak_id)');
        $this->addSql('CREATE TABLE messenger_messages (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, body CLOB NOT NULL, headers CLOB NOT NULL, queue_name VARCHAR(190) NOT NULL, created_at DATETIME NOT NULL --(DC2Type:datetime_immutable)
        , available_at DATETIME NOT NULL --(DC2Type:datetime_immutable)
        , delivered_at DATETIME DEFAULT NULL --(DC2Type:datetime_immutable)
        )');
        $this->addSql('CREATE INDEX IDX_75EA56E0FB7336F0 ON messenger_messages (queue_name)');
        $this->addSql('CREATE INDEX IDX_75EA56E0E3BD61CE ON messenger_messages (available_at)');
        $this->addSql('CREATE INDEX IDX_75EA56E016BA31DB ON messenger_messages (delivered_at)');
        $this->addSql('DROP TABLE cache');
        $this->addSql('DROP TABLE cache_locks');
        $this->addSql('DROP TABLE failed_jobs');
        $this->addSql('DROP TABLE job_batches');
        $this->addSql('DROP TABLE jobs');
        $this->addSql('DROP TABLE migrations');
        $this->addSql('DROP TABLE password_reset_tokens');
        $this->addSql('DROP TABLE personal_access_tokens');
        $this->addSql('DROP TABLE sessions');
        $this->addSql('DROP TABLE users');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE cache ("key" VARCHAR(255) NOT NULL COLLATE "BINARY", value CLOB NOT NULL COLLATE "BINARY", expiration INTEGER NOT NULL, PRIMARY KEY("key"))');
        $this->addSql('CREATE TABLE cache_locks ("key" VARCHAR(255) NOT NULL COLLATE "BINARY", owner VARCHAR(255) NOT NULL COLLATE "BINARY", expiration INTEGER NOT NULL, PRIMARY KEY("key"))');
        $this->addSql('CREATE TABLE failed_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, uuid VARCHAR(255) NOT NULL COLLATE "BINARY", connection CLOB NOT NULL COLLATE "BINARY", queue CLOB NOT NULL COLLATE "BINARY", payload CLOB NOT NULL COLLATE "BINARY", exception CLOB NOT NULL COLLATE "BINARY", failed_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)');
        $this->addSql('CREATE UNIQUE INDEX failed_jobs_uuid_unique ON failed_jobs (uuid)');
        $this->addSql('CREATE TABLE job_batches (id VARCHAR(255) NOT NULL COLLATE "BINARY", name VARCHAR(255) NOT NULL COLLATE "BINARY", total_jobs INTEGER NOT NULL, pending_jobs INTEGER NOT NULL, failed_jobs INTEGER NOT NULL, failed_job_ids CLOB NOT NULL COLLATE "BINARY", options CLOB DEFAULT NULL COLLATE "BINARY", cancelled_at INTEGER DEFAULT NULL, created_at INTEGER NOT NULL, finished_at INTEGER DEFAULT NULL, PRIMARY KEY(id))');
        $this->addSql('CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, queue VARCHAR(255) NOT NULL COLLATE "BINARY", payload CLOB NOT NULL COLLATE "BINARY", attempts INTEGER NOT NULL, reserved_at INTEGER DEFAULT NULL, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL)');
        $this->addSql('CREATE INDEX jobs_queue_index ON jobs (queue)');
        $this->addSql('CREATE TABLE migrations (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, migration VARCHAR(255) NOT NULL COLLATE "BINARY", batch INTEGER NOT NULL)');
        $this->addSql('CREATE TABLE password_reset_tokens (email VARCHAR(255) NOT NULL COLLATE "BINARY", token VARCHAR(255) NOT NULL COLLATE "BINARY", created_at DATETIME DEFAULT NULL, PRIMARY KEY(email))');
        $this->addSql('CREATE TABLE personal_access_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, tokenable_type VARCHAR(255) NOT NULL COLLATE "BINARY", tokenable_id INTEGER NOT NULL, name CLOB NOT NULL COLLATE "BINARY", token VARCHAR(255) NOT NULL COLLATE "BINARY", abilities CLOB DEFAULT NULL COLLATE "BINARY", last_used_at DATETIME DEFAULT NULL, expires_at DATETIME DEFAULT NULL, created_at DATETIME DEFAULT NULL, updated_at DATETIME DEFAULT NULL)');
        $this->addSql('CREATE UNIQUE INDEX personal_access_tokens_token_unique ON personal_access_tokens (token)');
        $this->addSql('CREATE INDEX personal_access_tokens_tokenable_type_tokenable_id_index ON personal_access_tokens (tokenable_type, tokenable_id)');
        $this->addSql('CREATE TABLE sessions (id VARCHAR(255) NOT NULL COLLATE "BINARY", user_id INTEGER DEFAULT NULL, ip_address VARCHAR(255) DEFAULT NULL COLLATE "BINARY", user_agent CLOB DEFAULT NULL COLLATE "BINARY", payload CLOB NOT NULL COLLATE "BINARY", last_activity INTEGER NOT NULL, PRIMARY KEY(id))');
        $this->addSql('CREATE INDEX sessions_last_activity_index ON sessions (last_activity)');
        $this->addSql('CREATE INDEX sessions_user_id_index ON sessions (user_id)');
        $this->addSql('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name VARCHAR(255) NOT NULL COLLATE "BINARY", email VARCHAR(255) NOT NULL COLLATE "BINARY", email_verified_at DATETIME DEFAULT NULL, password VARCHAR(255) NOT NULL COLLATE "BINARY", remember_token VARCHAR(255) DEFAULT NULL COLLATE "BINARY", created_at DATETIME DEFAULT NULL, updated_at DATETIME DEFAULT NULL, keycloak_id VARCHAR(255) DEFAULT NULL COLLATE "BINARY")');
        $this->addSql('CREATE UNIQUE INDEX users_keycloak_id_unique ON users (keycloak_id)');
        $this->addSql('CREATE UNIQUE INDEX users_email_unique ON users (email)');
        $this->addSql('DROP TABLE user');
        $this->addSql('DROP TABLE messenger_messages');
    }
}
