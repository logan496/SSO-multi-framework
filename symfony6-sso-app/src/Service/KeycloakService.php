<?php

namespace App\Service;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class KeycloakService
{
    private HttpClientInterface $httpClient;
    private CacheInterface $cache;
    private LoggerInterface $logger;
    private string $keycloakUrl;
    private string $realm;
    private string $clientId;
    private string $clientSecret;

    public function __construct(
        HttpClientInterface $httpClient,
        CacheInterface      $cache,
        LoggerInterface     $logger,
        string              $keycloakUrl,
        string              $realm,
        string              $clientId,
        string              $clientSecret


    )
    {
        $this->httpClient = $httpClient;
        $this->cache = $cache;
        $this->logger = $logger;

        $this->keycloakUrl = rtrim($keycloakUrl, '/');
        $this->realm = $realm;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Valider un token échangé auprès de Keycloak
     */
    public function validateExchangedToken(string $token): bool
    {
        try {
            // D'abord, vérifier le cache pour éviter les appels répétés
            $cacheKey = 'keycloak_token_valid_' . md5($token);

            return $this->cache->set($cacheKey, function (ItemInterface $item) use ($token) {
                $item->expiresAfter(300); // 5 minutes de cache

                // Appel à l'endpoint userinfo de Keycloak pour valider le token
                $response = $this->httpClient->request('POST',
                    $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid_connect/userinfo',
                    [
                        'headers' => [
                            'Authorization' => 'Bearer ' . $token,
                            'Content-Type' => 'application/x-www-form-urlencoded',
                        ],
                        'timeout' => 10,
                    ]
                );

                $isValid = $response->getStatusCode() === 200;

                if ($isValid) {
                    $userInfo = $response->toArray();
                    $this->logger->info('Token validé avec succès', [
                        'user_id' => $userInfo['sub'] ?? 'unknown',
                        'email' => $userInfo['email'] ?? 'unknown'
                    ]);
                } else {
                    $this->logger->warning('Token invalide', [
                        'status_code' => $response->getStatusCode()
                    ]);
                }

                return $isValid;
            });

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de la validation du token', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Valider le token via l'endpoint d'introspection (plus sécurisé)
     */
    public function introspectToken(string $token): ?array
    {
        try {
            $response = $this->httpClient->request('POST',
                $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid_connect/token/introspect',
                [
                    'body' => [
                        'token' => $token,
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                    ],
                    'timeout' => 10,
                ]
            );

            if ($response->getStatusCode() === 200) {
                $data = $response->toArray();

                // Vérifier que le token est actif
                if (isset($data['active']) && $data['active'] === true) {
                    return $data;
                }
            }

            return null;

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de l\'introspection du token', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Décoder un JWT token (validation locale, plus rapide)
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

            if (!$data) {
                return null;
            }

            // Vérifier l'expiration
            if (isset($data['exp']) && $data['exp'] < time()) {
                $this->logger->warning('Token expiré', [
                    'exp' => $data['exp'],
                    'current_time' => time()
                ]);
                return null;
            }

            // Vérifier l'audience (optionnel)
            if (isset($data['aud']) && !in_array($this->clientId, (array)$data['aud'])) {
                $this->logger->warning('Token avec audience incorrecte', [
                    'expected' => $this->clientId,
                    'actual' => $data['aud']
                ]);
                return null;
            }

            return $data;

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors du décodage du token', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Vérifier si l'utilisateur a un rôle spécifique
     */
    public function hasRole(string $token, string $role): bool
    {
        $tokenData = $this->decodeToken($token);

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
     * Obtenir tous les rôles de l'utilisateur depuis le token
     */
    public function getUserRoles(string $token): array
    {
        $tokenData = $this->decodeToken($token);

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
            $response = $this->httpClient->request('GET',
                $this->keycloakUrl . '/realms/' . $this->realm,
                ['timeout' => 10]
            );

            $isConnected = $response->getStatusCode() === 200;

            return [
                'connected' => $isConnected,
                'status' => $isConnected ? 'OK' : 'ERROR',
                'url' => $this->keycloakUrl,
                'realm' => $this->realm,
                'response_time' => null, // Symfony HTTP Client ne fournit pas facilement ce détail
            ];

        } catch (\Exception $e) {
            $this->logger->error('Erreur de connexion Keycloak', [
                'error' => $e->getMessage()
            ]);

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
     * Obtenir un token d'accès client pour les opérations administratives
     */
    public function getClientAccessToken(): ?string
    {
        try {
            $cacheKey = 'keycloak_client_token_' . $this->clientId;

            return $this->cache->get($cacheKey, function (ItemInterface $item) {
                $item->expiresAfter(3300); // 55 minutes, expire avant le vrai token

                $response = $this->httpClient->request('POST',
                    $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid_connect/token',
                    [
                        'body' => [
                            'grant_type' => 'client_credentials',
                            'client_id' => $this->clientId,
                            'client_secret' => $this->clientSecret,
                        ],
                        'timeout' => 10,
                    ]
                );

                if ($response->getStatusCode() === 200) {
                    $data = $response->toArray();
                    return $data['access_token'] ?? null;
                }

                return null;
            });

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de l\'obtention du token client', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Obtenir les informations utilisateur depuis le token
     */
    public function getUserInfo(string $token): ?array
    {
        try {
            $response = $this->httpClient->request('POST',
                $this->keycloakUrl . '/realms/' . $this->realm . '/protocol/openid_connect/userinfo',
                [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $token,
                    ],
                    'timeout' => 10,
                ]
            );

            if ($response->getStatusCode() === 200) {
                return $response->toArray();
            }

            return null;

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de la récupération des infos utilisateur', [
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Valider un token avec mise en cache intelligente
     */
    public function validateTokenWithCache(string $token): bool
    {
        // Décodage local d'abord (plus rapide)
        $tokenData = $this->decodeToken($token);

        if (!$tokenData) {
            return false;
        }

        // Si le token expire bientôt, valider auprès de Keycloak
        $expiresIn = ($tokenData['exp'] ?? 0) - time();

        if ($expiresIn < 300) { // Moins de 5 minutes
            return $this->validateExchangedToken($token);
        }

        // Sinon, le token local est suffisant
        return true;
    }
}
