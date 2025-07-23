<?php

namespace App\Service;

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

class KeycloakTokenValidatorService
{
    private HttpClientInterface $httpClient;
    private LoggerInterface $logger;
    private CacheInterface $cache;
    private string $keycloakUrl;
    private string $realm;
    private string $clientId;
    private string $clientSecret;

    public function __construct(
        LoggerInterface $logger,
        CacheInterface $cache,
        string $keycloakUrl,
        string $realm,
        string $clientId,
        string $clientSecret
    ) {
        $this->httpClient = HttpClient::create([
            'timeout' => 10,
            'max_redirects' => 0
        ]);
        $this->logger = $logger;
        $this->cache = $cache;
        $this->keycloakUrl = rtrim($keycloakUrl, '/');
        $this->realm = $realm;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Validate a token using Token Exchange v2 or fallback to introspection
     */
    public function validateExchangedToken(string $token): ?array
    {
        $cacheKey = 'validated_token_' . md5($token);

        $this->logger->info('KeycloakTokenValidator: Starting token validation (Exchange v2)', [
            'cache_key' => $cacheKey
        ]);

        try {
            return $this->cache->get($cacheKey, function (ItemInterface $item) use ($token) {
                $this->logger->info('KeycloakTokenValidator: Cache miss, validating token');

                // Try Token Exchange v2 validation first
                $tokenData = $this->validateWithTokenExchangeV2($token);

                // If Token Exchange v2 fails, fallback to standard introspection
                if (!$tokenData) {
                    $this->logger->info('KeycloakTokenValidator: Token Exchange v2 failed, falling back to introspection');
                    $tokenData = $this->introspectToken($token);
                }

                if (!$tokenData) {
                    $this->logger->warning('KeycloakTokenValidator: Both validation methods failed');
                    // Set a short TTL for failed validations to avoid hammering Keycloak
                    $item->expiresAfter(60);
                    return null;
                }

                // Validate token claims
                if (!$this->validateTokenClaims($tokenData)) {
                    $this->logger->warning('KeycloakTokenValidator: Token claims validation failed');
                    $item->expiresAfter(60);
                    return null;
                }

                $result = [
                    'valid' => true,
                    'user_id' => $tokenData['sub'] ?? null,
                    'username' => $tokenData['preferred_username'] ?? null,
                    'email' => $tokenData['email'] ?? null,
                    'roles' => $tokenData['realm_access']['roles'] ?? [],
                    'client_roles' => $tokenData['resource_access'][$this->clientId]['roles'] ?? [],
                    'expires_at' => $tokenData['exp'] ?? null,
                    'issued_at' => $tokenData['iat'] ?? null,
                    'audience' => $tokenData['aud'] ?? [],
                    'token_type' => $tokenData['typ'] ?? null,
                    'scope' => $tokenData['scope'] ?? null,
                ];

                // Set cache TTL based on token expiration, with a 30-second buffer
                $ttl = max(60, ($tokenData['exp'] ?? time() + 300) - time() - 30);
                $item->expiresAfter($ttl);

                $this->logger->info('KeycloakTokenValidator: Token validation successful and cached', [
                    'user_id' => $result['user_id'],
                    'username' => $result['username'],
                    'roles_count' => count($result['roles']),
                    'client_roles_count' => count($result['client_roles']),
                    'ttl' => $ttl,
                    'expires_at' => $tokenData['exp'] ?? null
                ]);

                return $result;
            });
        } catch (\Exception $e) {
            $this->logger->error('KeycloakTokenValidator: Cache error during token validation', [
                'error' => $e->getMessage()
            ]);
            // If cache fails, validate directly without caching
            return $this->validateTokenDirectly($token);
        }
    }

    /**
     * Validate token directly without caching (fallback method)
     */
    private function validateTokenDirectly(string $token): ?array
    {
        $this->logger->info('KeycloakTokenValidator: Direct validation (no cache)');

        // Try Token Exchange v2 validation first
        $tokenData = $this->validateWithTokenExchangeV2($token);

        // If Token Exchange v2 fails, fallback to standard introspection
        if (!$tokenData) {
            $this->logger->info('KeycloakTokenValidator: Token Exchange v2 failed, falling back to introspection');
            $tokenData = $this->introspectToken($token);
        }

        if (!$tokenData) {
            $this->logger->warning('KeycloakTokenValidator: Both validation methods failed');
            return null;
        }

        // Validate token claims
        if (!$this->validateTokenClaims($tokenData)) {
            $this->logger->warning('KeycloakTokenValidator: Token claims validation failed');
            return null;
        }

        $result = [
            'valid' => true,
            'user_id' => $tokenData['sub'] ?? null,
            'username' => $tokenData['preferred_username'] ?? null,
            'email' => $tokenData['email'] ?? null,
            'roles' => $tokenData['realm_access']['roles'] ?? [],
            'client_roles' => $tokenData['resource_access'][$this->clientId]['roles'] ?? [],
            'expires_at' => $tokenData['exp'] ?? null,
            'issued_at' => $tokenData['iat'] ?? null,
            'audience' => $tokenData['aud'] ?? [],
            'token_type' => $tokenData['typ'] ?? null,
            'scope' => $tokenData['scope'] ?? null,
        ];

        $this->logger->info('KeycloakTokenValidator: Token validation successful (direct)', [
            'user_id' => $result['user_id'],
            'username' => $result['username'],
            'roles_count' => count($result['roles']),
            'client_roles_count' => count($result['client_roles'])
        ]);

        return $result;
    }

    /**
     * Validate token using Keycloak Token Exchange v2
     */
    private function validateWithTokenExchangeV2(string $token): ?array
    {
        $url = sprintf(
            '%s/realms/%s/protocol/openid-connect/token',
            $this->keycloakUrl,
            $this->realm
        );

        $this->logger->info('KeycloakTokenValidator: Attempting Token Exchange v2 validation', [
            'url' => $url,
            'client_id' => $this->clientId
        ]);

        try {
            $response = $this->httpClient->request('POST', $url, [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query([
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'subject_token' => $token,
                    'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
                    'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
                ]),
            ]);

            $statusCode = $response->getStatusCode();

            if ($statusCode !== 200) {
                $this->logger->warning('KeycloakTokenValidator: Token Exchange v2 failed', [
                    'status_code' => $statusCode,
                    'response' => $response->getContent(false),
                    'url' => $url
                ]);
                return null;
            }

            $exchangeResponse = $response->toArray();

            if (!isset($exchangeResponse['access_token'])) {
                $this->logger->warning('KeycloakTokenValidator: Token Exchange v2 response missing access_token');
                return null;
            }

            // Decode the exchanged token to get user info
            $exchangedToken = $exchangeResponse['access_token'];
            $tokenData = $this->decodeJWT($exchangedToken);

            if (!$tokenData) {
                $this->logger->warning('KeycloakTokenValidator: Failed to decode exchanged token');
                return null;
            }

            $this->logger->info('KeycloakTokenValidator: Token Exchange v2 successful', [
                'user' => $tokenData['preferred_username'] ?? 'unknown',
                'expires_at' => $tokenData['exp'] ?? null,
                'token_type' => $exchangeResponse['token_type'] ?? null
            ]);

            return $tokenData;

        } catch (\Exception $e) {
            $this->logger->warning('KeycloakTokenValidator: Token Exchange v2 error', [
                'message' => $e->getMessage(),
                'url' => $url
            ]);
            return null;
        }
    }

    /**
     * Fallback: Standard token introspection
     */
    private function introspectToken(string $token): ?array
    {
        $url = sprintf(
            '%s/realms/%s/protocol/openid-connect/token/introspect',
            $this->keycloakUrl,
            $this->realm
        );

        $this->logger->info('KeycloakTokenValidator: Attempting standard token introspection', [
            'url' => $url,
            'client_id' => $this->clientId
        ]);

        try {
            $response = $this->httpClient->request('POST', $url, [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query([
                    'token' => $token,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ]),
            ]);

            $statusCode = $response->getStatusCode();

            if ($statusCode !== 200) {
                $this->logger->error('KeycloakTokenValidator: Token introspection failed', [
                    'status_code' => $statusCode,
                    'response' => $response->getContent(false),
                    'url' => $url
                ]);
                return null;
            }

            $data = $response->toArray();

            if (!($data['active'] ?? false)) {
                $this->logger->info('KeycloakTokenValidator: Token is not active');
                return null;
            }

            $this->logger->info('KeycloakTokenValidator: Token introspection successful', [
                'user' => $data['preferred_username'] ?? 'unknown',
                'expires_at' => $data['exp'] ?? null,
                'active' => $data['active'] ?? false
            ]);

            return $data;

        } catch (\Exception $e) {
            $this->logger->error('KeycloakTokenValidator: Token introspection error', [
                'message' => $e->getMessage(),
                'url' => $url
            ]);
            return null;
        }
    }

    /**
     * Decode JWT token (simplified - for production use a proper JWT library)
     */
    private function decodeJWT(string $token): ?array
    {
        try {
            $parts = explode('.', $token);

            if (count($parts) !== 3) {
                $this->logger->warning('KeycloakTokenValidator: Invalid JWT format');
                return null;
            }

            $payload = $parts[1];

            // Add padding if needed
            $payload = str_pad($payload, strlen($payload) % 4 === 0 ? strlen($payload) : strlen($payload) + 4 - strlen($payload) % 4, '=');

            $decoded = base64_decode($payload);

            if ($decoded === false) {
                $this->logger->warning('KeycloakTokenValidator: Failed to base64 decode JWT payload');
                return null;
            }

            $data = json_decode($decoded, true);

            if ($data === null) {
                $this->logger->warning('KeycloakTokenValidator: Failed to JSON decode JWT payload');
                return null;
            }

            $this->logger->info('KeycloakTokenValidator: JWT decoded successfully', [
                'sub' => $data['sub'] ?? 'unknown',
                'exp' => $data['exp'] ?? null,
                'iat' => $data['iat'] ?? null
            ]);

            return $data;

        } catch (\Exception $e) {
            $this->logger->error('KeycloakTokenValidator: JWT decode error', [
                'message' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Validate token claims
     */
    private function validateTokenClaims(array $tokenData): bool
    {
        $currentTime = time();

        // Check expiration
        $exp = $tokenData['exp'] ?? 0;
        if ($exp && $exp < $currentTime) {
            $this->logger->info('KeycloakTokenValidator: Token has expired', [
                'exp' => $exp,
                'now' => $currentTime,
                'expired_by' => $currentTime - $exp
            ]);
            return false;
        }

        // Check if token was issued in the future (with 60 second margin for clock skew)
        $iat = $tokenData['iat'] ?? 0;
        if ($iat && $iat > $currentTime + 60) {
            $this->logger->warning('KeycloakTokenValidator: Token issued in the future', [
                'iat' => $iat,
                'now' => $currentTime,
                'difference' => $iat - $currentTime
            ]);
            return false;
        }

        // Check not before (nbf) claim if present
        $nbf = $tokenData['nbf'] ?? 0;
        if ($nbf && $nbf > $currentTime + 60) {
            $this->logger->warning('KeycloakTokenValidator: Token not yet valid (nbf)', [
                'nbf' => $nbf,
                'now' => $currentTime,
                'valid_in' => $nbf - $currentTime
            ]);
            return false;
        }

        $this->logger->info('KeycloakTokenValidator: Token claims validation passed', [
            'exp' => $exp,
            'iat' => $iat,
            'nbf' => $nbf
        ]);

        return true;
    }

    /**
     * Extract Bearer token from Authorization header
     */
    public function extractBearerToken(string $authorizationHeader): ?string
    {
        if (!str_starts_with($authorizationHeader, 'Bearer ')) {
            return null;
        }

        return substr($authorizationHeader, 7);
    }

    /**
     * Check if user has a specific role
     */
    public function hasRole(array $validatedToken, string $role): bool
    {
        $roles = array_merge(
            $validatedToken['roles'] ?? [],
            $validatedToken['client_roles'] ?? []
        );

        return in_array($role, $roles);
    }

    /**
     * Check if user has any of the specified roles
     */
    public function hasAnyRole(array $validatedToken, array $roles): bool
    {
        $userRoles = array_merge(
            $validatedToken['roles'] ?? [],
            $validatedToken['client_roles'] ?? []
        );

        return !empty(array_intersect($userRoles, $roles));
    }

    /**
     * Get Keycloak configuration for debugging
     */
    public function getKeycloakConfiguration(): array
    {
        return [
            'keycloak_url' => $this->keycloakUrl,
            'realm' => $this->realm,
            'client_id' => $this->clientId,
            'token_exchange_url' => sprintf('%s/realms/%s/protocol/openid_connect/token', $this->keycloakUrl, $this->realm),
            'introspection_url' => sprintf('%s/realms/%s/protocol/openid_connect/token/introspect', $this->keycloakUrl, $this->realm),
        ];
    }
}
