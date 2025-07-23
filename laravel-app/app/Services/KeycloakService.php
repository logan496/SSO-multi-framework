<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class KeycloakService extends \App\Services\KeycloakTokenExchangeService
{
    private string $keycloakUrl;
    private string $realm;
    private string $clientId;
    private string $clientSecret;

    public function __construct()
    {
//
        $this->clientId = config('services.keycloak.client_id', 'laravel-client');
        $this->clientSecret = config('services.keycloak.client_secret', 'laravel-client');
        $this->keycloakUrl = config('services.keycloak.base_url', 'http://localhost:8080');
        $this->realm = config('services.keycloak.realms', 'laravel-client');
    }

    /**
     * Authentifier un utilisateur avec Keycloak
     */
    public function authenticate(string $username, string $password): ?array
    {
        try {
            $response = Http::asForm()->post(
                $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/token',
                [
                    'grant_type' => 'password',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'username' => $username,
                    'password' => $password,
                    'scope' => 'openid profile email',
                ]
            );

            if ($response->successful()) {
                $data = $response->json();

                // Cache le token pour éviter les multiples requêtes
                $cacheKey = 'keycloak_token_' . md5($username);
                Cache::put($cacheKey, $data, now()->addMinutes(55)); // 5 min avant expiration

                return $data;
            }

            Log::warning('Échec authentification Keycloak', [
                'username' => $username,
                'status' => $response->status(),
                'body' => $response->body()
            ]);

            return null;

        } catch (\Exception $e) {
            Log::error('Erreur authentification Keycloak: ' . $e->getMessage(), [
                'username' => $username
            ]);
            return null;
        }
    }

    /**
     * Rafraîchir un token d'accès
     */
    public function refreshToken(string $refreshToken): ?array
    {
        try {
            // Valider d'abord que le refresh token n'est pas vide
            if (empty($refreshToken)) {
                Log::warning('Refresh token vide fourni');
                return null;
            }

            $response = Http::asForm()->post(
                $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/token',
                [
                    'grant_type' => 'refresh_token',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'refresh_token' => $refreshToken,
                ]
            );

            if ($response->successful()) {
                $data = $response->json();

                Log::info('Token rafraîchi avec succès', [
                    'expires_in' => $data['expires_in'] ?? 'unknown',
                    'refresh_expires_in' => $data['refresh_expires_in'] ?? 'unknown'
                ]);

                return $data;
            }

            // Log détaillé de l'erreur
            $errorData = $response->json();
            Log::warning('Échec rafraîchissement token Keycloak', [
                'status' => $response->status(),
                'error' => $errorData['error'] ?? 'unknown',
                'error_description' => $errorData['error_description'] ?? 'unknown',
                'body' => $response->body()
            ]);

            return null;

        } catch (\Exception $e) {
            Log::error('Erreur rafraîchissement token Keycloak: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Valider un token d'accès Keycloak
     */
    public function validateToken(string $accessToken): bool
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $accessToken,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ])->post($this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/userinfo');

            return $response->successful();

        } catch (\Exception $e) {
            Log::error('Erreur validation token Keycloak: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Obtenir les informations utilisateur depuis le token
     */
    public function getUserInfo(string $accessToken): ?array
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $accessToken,
                'Content-Type' => 'application/x-www-form-urlencoded',
            ])->post($this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/userinfo');

            if ($response->successful()) {
                return $response->json();
            }

            return null;

        } catch (\Exception $e) {
            Log::error('Erreur récupération info utilisateur Keycloak: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Décoder un JWT token (sans validation cryptographique)
     */
    public function decodeToken(string $token): ?array
    {
        try {
            $parts = explode('.', $token);

            if (count($parts) !== 3) {
                return null;
            }

            $payload = base64_decode(strtr($parts[1], '-_', '+/'));
            $data = json_decode($payload, true);

            return $data ?: null;

        } catch (\Exception $e) {
            Log::error('Erreur décodage token JWT: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Vérifier si l'utilisateur a un rôle spécifique
     */
    public function hasRole(string $accessToken, string $role): bool
    {
        $tokenData = $this->decodeToken($accessToken);

        if (!$tokenData) {
            return false;
        }

        // Vérifier les rôles realm
        if (isset($tokenData['realm_access']['roles']) &&
            in_array($role, $tokenData['realm_access']['roles'])) {
            return true;
        }

        // Vérifier les rôles client
        if (isset($tokenData['resource_access'][$this->clientId]['roles']) &&
            in_array($role, $tokenData['resource_access'][$this->clientId]['roles'])) {
            return true;
        }

        return false;
    }

    /**
     * Obtenir tous les rôles de l'utilisateur
     */
    public function getUserRoles(string $accessToken): array
    {
        $tokenData = $this->decodeToken($accessToken);

        if (!$tokenData) {
            return [];
        }

        $roles = [];

        // Rôles realm
        if (isset($tokenData['realm_access']['roles'])) {
            $roles = array_merge($roles, $tokenData['realm_access']['roles']);
        }

        // Rôles client
        if (isset($tokenData['resource_access'][$this->clientId]['roles'])) {
            $roles = array_merge($roles, $tokenData['resource_access'][$this->clientId]['roles']);
        }

        return array_unique($roles);
    }

    /**
     * Vérifier la connexion à Keycloak
     */
    public function checkConnection(): array
    {
        try {
            $response = Http::timeout(10)->get($this->keycloakUrl . '/realms/' . $this->realm);

            $isConnected = $response->successful();

            return [
                'connected' => $isConnected,
                'status' => $isConnected ? 'OK' : 'ERROR',
                'url' => $this->keycloakUrl,
                'realm' => $this->realm,
                'response_time' => $response->handlerStats()['total_time'] ?? null,
            ];

        } catch (\Exception $e) {
            Log::error('Erreur connexion Keycloak: ' . $e->getMessage());

            return [
                'connected' => false,
                'status' => 'ERROR',
                'error' => $e->getMessage(),
                'url' => $this->keycloakUrl,
                'realm' => $this->realm,
            ];
        }
    }

    /**
     * Obtenir un token d'accès pour l'application (client credentials)
     */
    public function getClientAccessToken(): ?string
    {
        try {
            // Vérifier le cache d'abord
            $cacheKey = 'keycloak_client_token_' . $this->clientId;
            $cachedToken = Cache::get($cacheKey);

            if ($cachedToken) {
                return $cachedToken;
            }

            $response = Http::asForm()->post(
                $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/token',
                [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]
            );

            if ($response->successful()) {
                $data = $response->json();
                $token = $data['access_token'] ?? null;

                if ($token) {
                    // Cache le token (expire dans 55 minutes par sécurité)
                    $expiresIn = $data['expires_in'] ?? 3600;
                    Cache::put($cacheKey, $token, now()->addSeconds($expiresIn - 300));
                }

                return $token;
            }

            return null;

        } catch (\Exception $e) {
            Log::error('Erreur obtention token client Keycloak: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Créer un utilisateur dans Keycloak
     */
    public function createUser(array $userData): ?array
    {
        try {
            $adminToken = $this->getClientAccessToken();

            if (!$adminToken) {
                return null;
            }

            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $adminToken,
                'Content-Type' => 'application/json',
            ])->post(
                $this->keycloakUrl . '/admin/realms/' . $this->realm . '/users',
                $userData
            );

            if ($response->successful()) {
                return [
                    'success' => true,
                    'location' => $response->header('Location'),
                ];
            }

            return [
                'success' => false,
                'error' => $response->body(),
                'status' => $response->status(),
            ];

        } catch (\Exception $e) {
            Log::error('Erreur création utilisateur Keycloak: ' . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Déconnexion (révocation des tokens)
     */
    public function logout(?string $accessToken = null, ?string $refreshToken = null): bool
    {
        try {
            // Priorité au refresh token pour la déconnexion
            if ($refreshToken) {
                $response = Http::asForm()->post(
                    $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/logout',
                    [
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                        'refresh_token' => $refreshToken,
                    ]
                );

                return $response->successful();
            }

            // Si pas de refresh token, utiliser le token d'accès
            if ($accessToken) {
                $response = Http::withHeaders([
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ])->post(
                    $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid-connect/logout',
                    [
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                    ]
                );

                return $response->successful();
            }

            return false;

        } catch (\Exception $e) {
            Log::error('Erreur déconnexion Keycloak: ' . $e->getMessage());
            return false;
        }
    }


    /**
     * Vérifier si un token est valide
     */
    public function isTokenValid(string $token): bool
    {
        return $this->validateToken($token);
    }

    /**
     * Vérifier si un token est expiré
     */
    public function isTokenExpired(string $token): bool
    {
        $tokenData = $this->decodeToken($token);

        if (!$tokenData || !isset($tokenData['exp'])) {
            return true;
        }

        return $tokenData['exp'] < time();
    }

    /**
     * Obtenir l'ID utilisateur depuis le token
     */
    public function getUserIdFromToken(string $token): ?string
    {
        $tokenData = $this->decodeToken($token);

        return $tokenData['sub'] ?? null;
    }

    /**
     * Obtenir l'email de l'utilisateur depuis le token
     */
    public function getUserEmailFromToken(string $token): ?string
    {
        $tokenData = $this->decodeToken($token);

        return $tokenData['email'] ?? null;
    }
}
