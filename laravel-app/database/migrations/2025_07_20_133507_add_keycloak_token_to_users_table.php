<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Check if columns don't exist before adding them
            if (!Schema::hasColumn('users', 'keycloak_id')) {
                $table->string('keycloak_id')->nullable()->unique();
            }

            if (!Schema::hasColumn('users', 'keycloak_token')) {
                $table->text('keycloak_token')->nullable();
            }

            if (!Schema::hasColumn('users', 'keycloak_refresh_token')) {
                $table->text('keycloak_refresh_token')->nullable();
            }

            if (!Schema::hasColumn('users', 'keycloak_token_expires_at')) {
                $table->timestamp('keycloak_token_expires_at')->nullable();
            }

            if (!Schema::hasColumn('users', 'roles')) {
                $table->json('roles')->nullable();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $columns = [
                'keycloak_id',
                'keycloak_token',
                'keycloak_refresh_token',
                'keycloak_token_expires_at',
                'roles'
            ];

            foreach ($columns as $column) {
                if (Schema::hasColumn('users', $column)) {
                    $table->dropColumn($column);
                }
            }
        });
    }
};
