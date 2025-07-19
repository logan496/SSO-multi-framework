<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Migration pour préserver les utilisateurs existants de Laravel vers Symfony
 */
final class Version20250719000000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Préserve les utilisateurs existants lors de la migration Laravel vers Symfony';
    }

    public function up(Schema $schema): void
    {
        // Vérifier si l'ancienne table users existe encore
        $this->addSql('CREATE TABLE IF NOT EXISTS users_backup AS SELECT * FROM users WHERE 1=0'); // Table vide pour structure

        // Sauvegarder les données si la table users existe
        $this->addSql('INSERT OR IGNORE INTO users_backup SELECT * FROM users');

        // Créer la nouvelle table user (Symfony)
        $this->addSql('CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            email VARCHAR(180) NOT NULL,
            roles CLOB NOT NULL, -- (DC2Type:json)
            password VARCHAR(255) DEFAULT NULL,
            name VARCHAR(255) NOT NULL,
            keycloak_id VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL, -- (DC2Type:datetime_immutable)
            updated_at DATETIME NOT NULL  -- (DC2Type:datetime_immutable)
        )');

        // Créer les index
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649E7927C74 ON user (email)');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649491914B1 ON user (keycloak_id)');

        // Migrer les données SANS assigner de rôle par défaut
        // Les rôles seront gérés par Keycloak ou assignés manuellement
        $this->addSql("
            INSERT INTO user (email, roles, password, name, keycloak_id, created_at, updated_at)
            SELECT
                email,
                '[]' as roles,  -- Tableau vide, pas de rôle par défaut
                password,
                name,
                COALESCE(keycloak_id, '') as keycloak_id,
                COALESCE(created_at, datetime('now')) as created_at,
                COALESCE(updated_at, datetime('now')) as updated_at
            FROM users_backup
            WHERE email IS NOT NULL AND name IS NOT NULL
        ");

        // Créer la table messenger_messages
        $this->addSql('CREATE TABLE messenger_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            body CLOB NOT NULL,
            headers CLOB NOT NULL,
            queue_name VARCHAR(190) NOT NULL,
            created_at DATETIME NOT NULL, -- (DC2Type:datetime_immutable)
            available_at DATETIME NOT NULL, -- (DC2Type:datetime_immutable)
            delivered_at DATETIME DEFAULT NULL -- (DC2Type:datetime_immutable)
        )');

        $this->addSql('CREATE INDEX IDX_75EA56E0FB7336F0 ON messenger_messages (queue_name)');
        $this->addSql('CREATE INDEX IDX_75EA56E0E3BD61CE ON messenger_messages (available_at)');
        $this->addSql('CREATE INDEX IDX_75EA56E016BA31DB ON messenger_messages (delivered_at)');

        // Supprimer les anciennes tables Laravel
        $this->addSql('DROP TABLE IF EXISTS cache');
        $this->addSql('DROP TABLE IF EXISTS cache_locks');
        $this->addSql('DROP TABLE IF EXISTS failed_jobs');
        $this->addSql('DROP TABLE IF EXISTS job_batches');
        $this->addSql('DROP TABLE IF EXISTS jobs');
        $this->addSql('DROP TABLE IF EXISTS migrations');
        $this->addSql('DROP TABLE IF EXISTS password_reset_tokens');
        $this->addSql('DROP TABLE IF EXISTS personal_access_tokens');
        $this->addSql('DROP TABLE IF EXISTS sessions');
        $this->addSql('DROP TABLE IF EXISTS users');
        $this->addSql('DROP TABLE IF EXISTS users_backup');
    }

    public function down(Schema $schema): void
    {
        // Recréer les tables Laravel si nécessaire
        $this->addSql('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            email_verified_at DATETIME DEFAULT NULL,
            password VARCHAR(255) NOT NULL,
            remember_token VARCHAR(255) DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL,
            keycloak_id VARCHAR(255) DEFAULT NULL
        )');

        $this->addSql('CREATE UNIQUE INDEX users_keycloak_id_unique ON users (keycloak_id)');
        $this->addSql('CREATE UNIQUE INDEX users_email_unique ON users (email)');

        // Restaurer les données depuis la table user
        $this->addSql("
            INSERT INTO users (name, email, password, keycloak_id, created_at, updated_at)
            SELECT name, email, password, keycloak_id, created_at, updated_at
            FROM user
        ");

        // Supprimer les tables Symfony
        $this->addSql('DROP TABLE user');
        $this->addSql('DROP TABLE messenger_messages');

        // Recréer les autres tables Laravel (structure minimale)
        $this->addSql('CREATE TABLE cache ("key" VARCHAR(255) NOT NULL, value CLOB NOT NULL, expiration INTEGER NOT NULL, PRIMARY KEY("key"))');
        $this->addSql('CREATE TABLE sessions (id VARCHAR(255) NOT NULL, user_id INTEGER DEFAULT NULL, payload CLOB NOT NULL, last_activity INTEGER NOT NULL, PRIMARY KEY(id))');
        // ... autres tables si nécessaire
    }
}
