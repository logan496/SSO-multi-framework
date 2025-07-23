<?php

namespace App\Services;

use App\Services\KeycloakTokenExchangeService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;

class SymfonyApiService
{
    private KeycloakTokenExchangeService $tokenExchangeService;
    private string $symfonyBaseUrl;

    public function __construct(KeycloakTokenExchangeService $tokenExchangeService)
    {
        $this->tokenExchangeService = $tokenExchangeService;
        $this->symfonyBaseUrl = config('symfony.api_url');
    }

    /**
     * Récupérer les données du dashboard admin
     */
    public function getAdminDashboard(): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour getAdminDashboard');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/admin/api/dashboard',
            [],
            'GET'
        );
    }

    /**
     * Récupérer tous les utilisateurs
     */
    public function getAllUsers(): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour getAllUsers');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/admin/api/users',
            [],
            'GET'
        );
    }

    /**
     * Récupérer les informations système
     */
    public function getAdminSystem(): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour getAdminSystem');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/admin/api/system',
            [],
            'GET'
        );
    }

    /**
     * Récupérer les permissions
     */
    public function getAdminPermissions(): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour getAdminPermissions');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/admin/api/permissions',
            [],
            'GET'
        );
    }

    /**
     * Vérifier la santé de l'API Symfony
     */
    public function checkApiHealth(): bool
    {
        try {
            // Pour le health check, on peut utiliser un endpoint public ou un token système
            $response = Http::timeout(10)->get($this->symfonyBaseUrl . '/health');
            
            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Erreur lors du health check Symfony API', [
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Créer un utilisateur via l'API Symfony
     */
    public function createUser(array $userData): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour createUser');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/admin/api/users',
            $userData,
            'POST'
        );
    }

    /**
     * Mettre à jour un utilisateur
     */
    public function updateUser(int $userId, array $userData): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour updateUser');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            "/admin/api/users/{$userId}",
            $userData,
            'PUT'
        );
    }

    /**
     * Supprimer un utilisateur
     */
    public function deleteUser(int $userId): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour deleteUser');
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', ['user_id' => $user->id]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            "/admin/api/users/{$userId}",
            [],
            'DELETE'
        );
    }

    /**
     * Appel générique à l'API Symfony avec gestion automatique des tokens
     */
    public function callApi(string $endpoint, array $data = [], string $method = 'GET'): ?array
    {
        if (!Auth::check()) {
            Log::error('Utilisateur non authentifié pour callApi', [
                'endpoint' => $endpoint,
                'method' => $method
            ]);
            return null;
        }

        $user = Auth::user();
        
        if (!$user->hasValidKeycloakToken()) {
            if (!$user->refreshKeycloakTokenIfNeeded()) {
                Log::error('Impossible de rafraîchir le token Keycloak', [
                    'user_id' => $user->id,
                    'endpoint' => $endpoint
                ]);
                return null;
            }
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            $endpoint,
            $data,
            $method
        );
    }
}

<?php

namespace App\EventListener;

use App\Service\KeycloakService;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakTokenListener
{
    private KeycloakService $keycloakService;
    private TokenStorageInterface $tokenStorage;
    private UserProviderInterface $userProvider;
    private LoggerInterface $logger;

    public function __construct(
        KeycloakService $keycloakService,
        TokenStorageInterface $tokenStorage,
        UserProviderInterface $userProvider,
        LoggerInterface $logger
    ) {
        $this->keycloakService = $keycloakService;
        $this->tokenStorage = $tokenStorage;
        $this->userProvider = $userProvider;
        $this->logger = $logger;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();

        // Vérifier seulement les routes API qui nécessitent une authentification
        if (!$this->shouldValidateToken($request)) {
            return;
        }

        try {
            $token = $this->extractTokenFromRequest($request);

            if (!$token) {
                $this->handleUnauthorized($event, 'Token manquant');
                return;
            }

            // Valider le token auprès de Keycloak
            if (!$this->keycloakService->validateExchangedToken($token)) {
                $this->handleUnauthorized($event, 'Token invalide');
                return;
            }

            // Extraire les informations utilisateur du token
            $userInfo = $this->keycloakService->decodeToken($token);
            
            if (!$userInfo) {
                $this->handleUnauthorized($event, 'Impossible de décoder le token');
                return;
            }

            // Créer un token d'authentification Symfony
            $this->authenticateUser($userInfo, $token);

            $this->logger->info('Token Keycloak validé avec succès', [
                'user_id' => $userInfo['sub'] ?? 'unknown',
                'email' => $userInfo['email'] ?? 'unknown',
                'route' => $request->get('_route')
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de la validation du token Keycloak', [
                'error' => $e->getMessage(),
                'route' => $request->get('_route'),
                'uri' => $request->getRequestUri()
            ]);

            $this->handleUnauthorized($event, 'Erreur de validation du token');
        }
    }

    private function shouldValidateToken(Request $request): bool
    {
        $path = $request->getPathInfo();
        
        // Routes qui nécessitent une validation de token
        $protectedRoutes = [
            '/admin/api/',
            '/api/protected/',
            '/user/api/'
        ];

        // Routes exclues de la validation
        $excludedRoutes = [
            '/health',
            '/api/public/',
            '/login',
            '/logout'
        ];

        // Vérifier les exclusions d'abord
        foreach ($excludedRoutes as $excludedRoute) {
            if (str_starts_with($path, $excludedRoute)) {
                return false;
            }
        }

        // Vérifier les routes protégées
        foreach ($protectedRoutes as $protectedRoute) {
            if (str_starts_with($path, $protectedRoute)) {
                return true;
            }
        }

        return false;
    }

    private function extractTokenFromRequest(Request $request): ?string
    {
        $authHeader = $request->headers->get('Authorization');

        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        return substr($authHeader, 7);
    }

    private function authenticateUser(array $userInfo, string $token): void
    {
        try {
            // Créer un utilisateur temporaire avec les infos du token
            $user = new \App\Entity\User();
            $user->setEmail($userInfo['email'] ?? '');
            $user->setKeycloakId($userInfo['sub'] ?? '');
            
            // Extraire les rôles du token
            $roles = $this->extractRolesFromToken($userInfo);
            $user->setRoles($roles);

            // Créer le token d'authentification Symfony
            $authToken = new PreAuthenticatedToken(
                $user,
                'keycloak',
                $roles
            );

            // Stocker le token Keycloak pour une utilisation ultérieure
            $authToken->setAttribute('keycloak_token', $token);
            $authToken->setAttribute('keycloak_user_info', $userInfo);

            $this->tokenStorage->setToken($authToken);

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors de l\'authentification utilisateur', [
                'error' => $e->getMessage(),
                'user_info' => $userInfo
            ]);
            throw $e;
        }
    }

    private function extractRolesFromToken(array $tokenData): array
    {
        $roles = ['ROLE_USER']; // Rôle par défaut

        // Rôles realm
        if (isset($tokenData['realm_access']['roles'])) {
            foreach ($tokenData['realm_access']['roles'] as $role) {
                $roles[] = 'ROLE_' . strtoupper($role);
            }
        }

        // Rôles client (si configuré)
        $clientId = $_ENV['KEYCLOAK_CLIENT_ID'] ?? 'symfony-app';
        if (isset($tokenData['resource_access'][$clientId]['roles'])) {
            foreach ($tokenData['resource_access'][$clientId]['roles'] as $role) {
                $roles[] = 'ROLE_' . strtoupper($role);
            }
        }

        return array_unique($roles);
    }

    private function handleUnauthorized(RequestEvent $event, string $message): void
    {
        $this->logger->warning('Accès non autorisé', [
            'message' => $message,
            'uri' => $event->getRequest()->getRequestUri(),
            'ip' => $event->getRequest()->getClientIp()
        ]);

        $response = new JsonResponse([
            'error' => 'Unauthorized',
            'message' => $message,
            'code' => 401
        ], Response::HTTP_UNAUTHORIZED);

        $event->setResponse($response);
    }
}

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
        CacheInterface $cache,
        LoggerInterface $logger
    ) {
        $this->httpClient = $httpClient;
        $this->cache = $cache;
        $this->logger = $logger;
        
        $this->keycloakUrl = rtrim($_ENV['KEYCLOAK_URL'] ?? 'http://localhost:8080', '/');
        $this->realm = $_ENV['KEYCLOAK_REALM'] ?? 'master';
        $this->clientId = $_ENV['KEYCLOAK_CLIENT_ID'] ?? '';
        $this->clientSecret = $_ENV['KEYCLOAK_CLIENT_SECRET'] ?? '';
    }

    /**
     * Valider un token échangé auprès de Keycloak
     */
    public function validateExchangedToken(string $token): bool
    {
        try {
            // D'abord, vérifier le cache pour éviter les appels répétés
            $cacheKey = 'keycloak_token_valid_' . md5($token);
            
            return $this->cache->get($cacheKey, function (ItemInterface $item) use ($token) {
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
