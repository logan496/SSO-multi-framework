<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Log;
use Laravel\Sanctum\HasApiTokens;
use App\Services\KeycloakService;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'keycloak_id',
        'keycloak_token',
        'keycloak_refresh_token',
        'keycloak_token_expires_at',
        'roles',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'keycloak_token',
        'keycloak_refresh_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'keycloak_token_expires_at' => 'datetime',
        'roles' => 'array',
        'password' => 'hashed',
    ];

    /**
     * Check if user has a specific role
     */
    public function hasRole(string $role): bool
    {
        $userRoles = $this->roles ?? [];
        return in_array($role, $userRoles);
    }

    /**
     * Check if user has any of the specified roles
     */
    public function hasAnyRole(array $roles): bool
    {
        $userRoles = $this->roles ?? [];
        return !empty(array_intersect($roles, $userRoles));
    }

    /**
     * Get all user roles
     */
    public function getAllRoles(): array
    {
        return $this->roles ?? [];
    }

    /**
     * Check if Keycloak token is valid (not expired)
     */
    public function hasValidKeycloakToken(): bool
    {
        if (empty($this->keycloak_token)) {
            return false;
        }

        if (empty($this->keycloak_token_expires_at)) {
            return false;
        }

        return $this->keycloak_token_expires_at > now();
    }

    /**
     * Refresh Keycloak token if needed
     */
    public function refreshKeycloakTokenIfNeeded(): bool
    {
        if ($this->hasValidKeycloakToken()) {
            return true; // Token still valid
        }

        if (empty($this->keycloak_refresh_token)) {
            Log::warning('Pas de refresh token disponible', ['user_id' => $this->id]);
            return false; // No refresh token available
        }

        try {
            $keycloakService = app(KeycloakService::class);
            $tokenData = $keycloakService->refreshToken($this->keycloak_refresh_token);

            if (!$tokenData) {
                Log::warning('Impossible de rafraichir le token Keycloak', [
                    'user_id' => $this->id
                ]);

                // Nettoyer les tokens invalides
                $this->update([
                    'keycloak_token' => null,
                    'keycloak_refresh_token' => null,
                    'keycloak_token_expires_at' => null,
                ]);

                return false;
            }

            // Update tokens
            $this->update([
                'keycloak_token' => $tokenData['access_token'],
                'keycloak_refresh_token' => $tokenData['refresh_token'] ?? $this->keycloak_refresh_token,
                'keycloak_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 3600),
            ]);

            Log::info('Token utilisateur rafraîchi avec succès', [
                'user_id' => $this->id,
                'expires_at' => $this->keycloak_token_expires_at
            ]);

            return true;

        } catch (\Exception $e) {
            Log::error('Erreur rafraîchissement token utilisateur: ' . $e->getMessage(), [
                'user_id' => $this->id
            ]);

            // En cas d'erreur, nettoyer les tokens
            $this->update([
                'keycloak_token' => null,
                'keycloak_refresh_token' => null,
                'keycloak_token_expires_at' => null,
            ]);

            return false;
        }
    }

    /**
     * Get user's primary role (first role in the list)
     */
    public function getPrimaryRole(): ?string
    {
        $roles = $this->getAllRoles();
        return empty($roles) ? null : $roles[0];
    }

    /**
     * Check if user is admin
     */
    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    /**
     * Check if user is manager
     */
    public function isManager(): bool
    {
        return $this->hasRole('manager');
    }

    /**
     * Check if user is a regular user
     */
    public function isUser(): bool
    {
        return $this->hasRole('user');
    }
}
