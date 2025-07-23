<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class KeycloakTokenExchangeService
{
    private string $keycloakUrl;
    private string $realm;
    private string $clientId;
    private string $clientSecret;

    public function __construct()
    {
        $this->keycloakUrl = config('services.keycloak.base_url', 'http://localhost:8080');
        $this->realm = config('services.keycloak.realms', 'multiframework-sso');
        $this->clientId = config('services.keycloak.client_id', 'laravel-client');
        $this->clientSecret = config('services.keycloak.client_secret', 'CCj84nHbL578idrbOphEW2nNpj50t2YG');
    }

    /**
     * Vérifie si le token exchange standard est disponible
     */
    public function checkTokenExchangeSupport(): array
    {
        $url = "{$this->keycloakUrl}/realms/{$this->realm}/.well-known/openid-configuration";

        try {
            $response = Http::get($url);

            if ($response->successful()) {
                $config = $response->json();
                $supportedGrantTypes = $config['grant_types_supported'] ?? [];

                return [
                    'standard_supported' => in_array('urn:ietf:params:oauth:grant-type:token-exchange', $supportedGrantTypes),
                    'legacy_supported' => true,
                    'grant_types' => $supportedGrantTypes,
                    'token_endpoint' => $config['token_endpoint'] ?? null
                ];
            }

            return ['error' => 'Cannot fetch Keycloak configuration'];

        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Échange un token utilisateur contre un token pour communiquer avec Symfony
     * Utilise le Standard Token Exchange (V2)
     */
    public function exchangeTokenForSymfony(string $userToken): ?array
    {
        $url = "{$this->keycloakUrl}/realms/{$this->realm}/protocol/openid-connect/token";

        // Fix: Use consistent config key
        $audience = config('services.keycloak.symfony_audience') ?? config('keycloak.symfony_audience');

        if (!$audience) {
            Log::error('Symfony audience not configured', [
                'checked_keys' => ['services.keycloak.symfony_audience', 'keycloak.symfony_audience']
            ]);
            return null;
        }

        // Paramètres pour le Standard Token Exchange
        $params = [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'subject_token' => $userToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'audience' => $audience,
            'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        ];

        Log::info('Attempting token exchange', [
            'url' => $url,
            'grant_type' => $params['grant_type'],
            'audience' => $audience,
            'client_id' => $this->clientId
        ]);

        try {
            $response = Http::asForm()
                ->timeout(30)
                ->post($url, $params);

            if ($response->successful()) {
                $data = $response->json();

                Log::info('Token exchange successful for Symfony', [
                    'audience' => $audience,
                    'token_type' => $data['token_type'] ?? 'unknown',
                ]);

                return [
                    'access_token' => $data['access_token'],
                    'token_type' => $data['token_type'] ?? 'Bearer',
                    'expires_in' => $data['expires_in'] ?? 300,
                    'scope' => $data['scope'] ?? '',
                ];
            }

            // Log détaillé de l'erreur
            Log::error('Token exchange failed for Symfony', [
                'status' => $response->status(),
                'response' => $response->body(),
                'url' => $url,
                'client_id' => $this->clientId,
                'audience' => $audience
            ]);

            // Handle specific error cases
            $responseBody = $response->body();

            if ($response->status() === 404 && str_contains($responseBody, 'Protocol not found')) {
                Log::warning('Standard token exchange endpoint not found, trying alternative approach');
                return $this->tryAlternativeTokenExchange($userToken);
            }

            if ($response->status() === 400) {
                $errorData = $response->json();
                $error = $errorData['error'] ?? 'unknown';
                $errorDescription = $errorData['error_description'] ?? '';

                if ($error === 'invalid_client' || str_contains($errorDescription, 'not allowed')) {
                    Log::error('Token exchange not allowed - check client configuration', [
                        'error' => $error,
                        'description' => $errorDescription,
                        'suggestion' => 'Enable token exchange in Keycloak client settings'
                    ]);
                }
            }

            return null;

        } catch (\Exception $e) {
            Log::error('Token exchange error for Symfony', [
                'message' => $e->getMessage(),
                'url' => $url
            ]);
            return null;
        }
    }

    /**
     * Méthode alternative si le token exchange standard n'est pas disponible
     */
    private function tryAlternativeTokenExchange(string $userToken): ?array
    {
        Log::info('Trying alternative token approach - direct token validation');

        // Alternative 1: Valider le token et le réutiliser directement
        if ($this->validateToken($userToken)) {
            Log::info('Using original token directly as alternative');

            // Get token info for better expiration handling
            $tokenInfo = $this->getTokenInfo($userToken);
            $expiresIn = $tokenInfo['exp'] ?? 300;

            return [
                'access_token' => $userToken,
                'token_type' => 'Bearer',
                'expires_in' => $expiresIn,
                'scope' => '',
                'note' => 'direct_token_reuse'
            ];
        }

        // Alternative 2: Try client credentials flow for service-to-service communication
        return $this->tryClientCredentialsFlow();
    }

    /**
     * Try client credentials flow as fallback
     */
    private function tryClientCredentialsFlow(): ?array
    {
        $url = "{$this->keycloakUrl}/realms/{$this->realm}/protocol/openid-connect/token";

        $params = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        Log::info('Trying client credentials flow as fallback');

        try {
            $response = Http::asForm()->post($url, $params);

            if ($response->successful()) {
                $data = $response->json();

                Log::info('Client credentials flow successful', [
                    'token_type' => $data['token_type'] ?? 'unknown',
                ]);

                return [
                    'access_token' => $data['access_token'],
                    'token_type' => $data['token_type'] ?? 'Bearer',
                    'expires_in' => $data['expires_in'] ?? 300,
                    'scope' => $data['scope'] ?? '',
                    'note' => 'client_credentials_fallback'
                ];
            }

            Log::error('Client credentials flow failed', [
                'status' => $response->status(),
                'response' => $response->body()
            ]);

        } catch (\Exception $e) {
            Log::error('Client credentials flow error', ['error' => $e->getMessage()]);
        }

        return null;
    }

    /**
     * Get token information (decode JWT payload)
     */
    private function getTokenInfo(string $token): array
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return [];
            }

            $payload = json_decode(base64_decode($parts[1]), true);
            return $payload ?? [];

        } catch (\Exception $e) {
            Log::warning('Cannot decode token payload', ['error' => $e->getMessage()]);
            return [];
        }
    }

    /**
     * Valide un token auprès de Keycloak
     */
    private function validateToken(string $token): bool
    {
        $url = "{$this->keycloakUrl}/realms/{$this->realm}/protocol/openid-connect/userinfo";

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $token
            ])->timeout(10)->get($url);

            return $response->successful();

        } catch (\Exception $e) {
            Log::error('Token validation failed', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Appelle l'API Symfony avec le token échangé
     */
    public function callSymfonyApi(string $userToken, string $endpoint, array $data = [], string $method = 'GET'): ?array
    {
        // Récupère ou génère le token échangé
        $exchangedToken = $this->getOrExchangeToken($userToken);

        if (!$exchangedToken) {
            Log::error('Token exchange failed - no exchanged token available');
            return null;
        }

        $symfonyBaseUrl = config('services.symfony.base_url');
        if (!$symfonyBaseUrl) {
            Log::error('Configuration services.symfony.base_url manquante');
            return null;
        }

        $url = rtrim($symfonyBaseUrl, '/') . $endpoint;

        Log::info('Calling Symfony API', [
            'url' => $url,
            'method' => $method,
            'endpoint' => $endpoint,
            'token_note' => $exchangedToken['note'] ?? 'standard_exchange'
        ]);

        try {
            $request = Http::withHeaders([
                'Authorization' => 'Bearer ' . $exchangedToken['access_token'],
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])->timeout(config('services.symfony.timeout', 30));

            $response = match(strtoupper($method)) {
                'GET' => $request->get($url, $data),
                'POST' => $request->post($url, $data),
                'PUT' => $request->put($url, $data),
                'DELETE' => $request->delete($url, $data),
                default => throw new \InvalidArgumentException("Méthode HTTP non supportée: $method")
            };

            if ($response->successful()) {
                Log::info('Symfony API call successful', [
                    'endpoint' => $endpoint,
                    'method' => $method,
                    'status' => $response->status(),
                ]);
                return $response->json();
            }

            // Si le token a expiré, essaie de le renouveler une seule fois
            if ($response->status() === 401 && !isset($data['_retry'])) {
                Log::info('Token expired, trying to refresh');
                $this->clearCachedToken($userToken);

                // Récursion avec nouveau token (éviter boucle infinie)
                $data['_retry'] = true;
                return $this->callSymfonyApi($userToken, $endpoint, $data, $method);
            }

            Log::error('Symfony API call failed', [
                'endpoint' => $endpoint,
                'status' => $response->status(),
                'response' => $response->body(),
            ]);
            return null;

        } catch (\Exception $e) {
            Log::error('Symfony API call error', [
                'endpoint' => $endpoint,
                'message' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Récupère le token depuis le cache ou l'échange
     */
    private function getOrExchangeToken(string $userToken): ?array
    {
        $cacheKey = 'symfony_token_' . md5($userToken);

        // Vérifie le cache
        $cachedToken = Cache::get($cacheKey);
        if ($cachedToken && $this->isTokenValid($cachedToken)) {
            return $cachedToken;
        }

        // Échange le token
        $exchangedToken = $this->exchangeTokenForSymfony($userToken);

        if ($exchangedToken) {
            // Met en cache avec une marge de sécurité
            $ttl = max(60, ($exchangedToken['expires_in'] ?? 300) - 30);
            Cache::put($cacheKey, $exchangedToken, $ttl);
        }

        return $exchangedToken;
    }

    /**
     * Vérifie si le token est encore valide
     */
    private function isTokenValid(array $tokenData): bool
    {
        if (empty($tokenData['access_token'])) {
            return false;
        }

        // Check if we have expiration info
        if (isset($tokenData['cached_at']) && isset($tokenData['expires_in'])) {
            $expirationTime = $tokenData['cached_at'] + $tokenData['expires_in'] - 30; // 30s margin
            return time() < $expirationTime;
        }

        return true; // Assume valid if no expiration info
    }

    /**
     * Supprime le token du cache
     */
    private function clearCachedToken(string $userToken): void
    {
        $cacheKey = 'symfony_token_' . md5($userToken);
        Cache::forget($cacheKey);
    }

    /**
     * Méthode de diagnostic complète
     */
    public function diagnoseTokenExchange(): array
    {
        $supportCheck = $this->checkTokenExchangeSupport();

        return [
            'config' => [
                'keycloak_url' => $this->keycloakUrl,
                'realm' => $this->realm,
                'client_id' => $this->clientId,
                'symfony_audience' => config('services.keycloak.symfony_audience') ?? config('keycloak.symfony_audience'),
                'has_client_secret' => !empty($this->clientSecret),
            ],
            'support_check' => $supportCheck,
            'recommendations' => $this->getConfigurationRecommendations($supportCheck)
        ];
    }


}
