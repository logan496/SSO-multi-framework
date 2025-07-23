<?php
//
//namespace App\Services;
//
//use Illuminate\Support\Facades\Auth;
//use Illuminate\Support\Facades\Http;
//use Illuminate\Support\Facades\Log;
//use Illuminate\Support\Facades\Cache;
//
//class SymfonyApiService
//{
//    private string $baseUrl;
//    private int $timeout;
//    private KeycloakService $keycloakService;
//
//    public function __construct(KeycloakService $keycloakService)
//    {
//        $this->baseUrl = rtrim(config('services.symfony.base_url', 'http://localhost:8003'), '/');
//        $this->timeout = config('services.symfony.timeout', 30);
//        $this->keycloakService = $keycloakService;
//    }
//
//    /**
//     * Obtenir le token d'authentification valide
//     */
//    private function getValidAuthToken(): ?string
//    {
//        $user = Auth::user();
//
//        if (!$user || !$user->keycloak_token) {
//            Log::warning('Utilisateur non authentifié ou sans token Keycloak');
//            return null;
//        }
//
//        // Vérifier si le token est encore valide
//        if ($user->keycloak_token_expires_at && $user->keycloak_token_expires_at->isPast()) {
//            Log::info('Token Keycloak expiré, tentative de renouvellement');
//
//            // Essayer de renouveler le token
//            if (!$user->refreshKeycloakTokenIfNeeded()) {
//                Log::error('Impossible de renouveler le token Keycloak');
//                return null;
//            }
//
//            // Recharger l'utilisateur après le renouvellement
//            $user->refresh();
//        }
//
//        return $user->keycloak_token;
//    }
//
//    /**
//     * Obtenir les headers d'authentification
//     */
//    private function getAuthHeaders(): array
//    {
//        $headers = [
//            'Accept' => 'application/json',
//            'Content-Type' => 'application/json',
//            'User-Agent' => 'Laravel-SSO-App/1.0',
//            'X-Requested-With' => 'XMLHttpRequest'
//        ];
//
//        $token = $this->getValidAuthToken();
//        if ($token) {
//            $headers['Authorization'] = 'Bearer ' . $token;
//        }
//
//        return $headers;
//    }
//
//    /**
//     * Effectuer une requête HTTP vers l'API Symfony
//     */
//    private function makeRequest(string $endpoint, array $options = []): ?array
//    {
//        try {
//            $url = $this->baseUrl . $endpoint;
//
//            // Log de la tentative de requête
//            Log::info("Requête Symfony API", [
//                'url' => $url,
//                'method' => $options['method'] ?? 'GET',
//                'user_id' => Auth::id()
//            ]);
//
//            $headers = $this->getAuthHeaders();
//
//            // Vérifier que nous avons un token d'authentification
//            if (!isset($headers['Authorization'])) {
//                Log::error('Token d\'authentification manquant pour la requête Symfony');
//                return null;
//            }
//
//            // Configurer la requête HTTP
//            $httpClient = Http::withHeaders($headers)
//                ->timeout($this->timeout)
//                ->retry(2, 1000); // 2 essais avec 1s d'intervalle
//
//            // Effectuer la requête selon la méthode
//            $method = strtoupper($options['method'] ?? 'GET');
//
//            switch ($method) {
//                case 'POST':
//                    $response = $httpClient->post($url, $options['data'] ?? []);
//                    break;
//                case 'PUT':
//                    $response = $httpClient->put($url, $options['data'] ?? []);
//                    break;
//                case 'DELETE':
//                    $response = $httpClient->delete($url);
//                    break;
//                default:
//                    $response = $httpClient->get($url, $options['query'] ?? []);
//            }
//
//            // Log détaillé de la réponse
//            Log::debug("Réponse Symfony API", [
//                'url' => $url,
//                'status' => $response->status(),
//                'headers' => $response->headers(),
//                'body_size' => strlen($response->body())
//            ]);
//
//            // Vérification du statut HTTP
//            if ($response->status() === 401) {
//                Log::error('Erreur 401 - Token invalide ou expiré', [
//                    'url' => $url,
//                    'user_id' => Auth::id()
//                ]);
//                return null;
//            }
//
//            if (!$response->successful()) {
//                Log::error("Erreur HTTP Symfony API", [
//                    'url' => $url,
//                    'status' => $response->status(),
//                    'body' => $response->body()
//                ]);
//                return null;
//            }
//
//            // Vérifier que la réponse est du JSON
//            $contentType = $response->header('Content-Type', '');
//            if (!str_contains($contentType, 'application/json')) {
//                Log::error("Réponse non-JSON depuis Symfony", [
//                    'url' => $url,
//                    'content_type' => $contentType
//                ]);
//                return null;
//            }
//
//            $data = $response->json();
//
//            if (!$data) {
//                Log::error("Impossible de décoder la réponse JSON", ['url' => $url]);
//                return null;
//            }
//
//            return $data;
//
//        } catch (\Exception $e) {
//            Log::error("Exception lors de la requête Symfony API", [
//                'url' => $url ?? 'unknown',
//                'error' => $e->getMessage(),
//                'trace' => $e->getTraceAsString()
//            ]);
//            return null;
//        }
//    }
//
//    /**
//     * Vérifier la santé de l'API Symfony
//     */
//    public function checkApiHealth(): bool
//    {
//        try {
//            // Utiliser un endpoint de santé simple sans authentification
//            $response = Http::timeout(10)->get($this->baseUrl . '/health');
//            return $response->successful();
//        } catch (\Exception $e) {
//            Log::error('Erreur vérification santé Symfony API: ' . $e->getMessage());
//            return false;
//        }
//    }
//
//    /**
//     * Test de connectivité avec authentification
//     */
//    public function testAuthenticatedConnection(): array
//    {
//        try {
//            $result = $this->makeRequest('/admin/api/health');
//
//            if ($result) {
//                return [
//                    'success' => true,
//                    'status' => 'authenticated_connection_ok',
//                    'data' => $result
//                ];
//            }
//
//            return [
//                'success' => false,
//                'status' => 'authentication_failed'
//            ];
//
//        } catch (\Exception $e) {
//            return [
//                'success' => false,
//                'status' => 'connection_error',
//                'error' => $e->getMessage()
//            ];
//        }
//    }
//
//    /**
//     * Dashboard Admin
//     */
//    public function getAdminDashboard(): ?array
//    {
//        return $this->makeRequest('/admin/api/dashboard');
//    }
//
//    /**
//     * Liste des permissions
//     */
//    public function getAdminSystem(): ?array
//    {
////        return $this->makeRequest('/admin/api/users');
//        try {
//            $response = Http::timeout($this->timeout)
//                ->withHeaders([
//                    'Accept' => 'application/json',
//                    'Content-Type' => 'application/json',
//                    'X-API-Key' => config('services.symfony.api_key', '')
//                ])
//                ->get("{$this->baseUrl}/test/system");
//
//            if ($response->successful()) {
//                $data = $response->json();
//
//                Log::info('Symfony API Response', ['data' => $data]);
//
//                return $data;
//            }
//
//            Log::error('Symfony API Error', [
//                'status' => $response->status(),
//                'body' => $response->body()
//            ]);
//
//            return null;
//        } catch (\Exception $e) {
//            Log::error('Symfony API Exception', [
//                'message' => $e->getMessage(),
//                'trace' => $e->getTraceAsString()
//            ]);
//
//            throw $e;
//        }
//    }
//
//    /**
//     * Récupère tous les utilisateurs depuis l'API Symfony
//     */
//    public function getAllUsers(): ?array
//    {
//        try {
//            $response = Http::timeout($this->timeout)
//                ->withHeaders([
//                    'Accept' => 'application/json',
//                    'Content-Type' => 'application/json',
//                    'X-API-Key' => config('services.symfony.api_key', ''),
//                ])
//                ->get("{$this->baseUrl}/test/free");
//
//            if ($response->successful()) {
//                $data = $response->json();
//
//                // Log pour déboguer
//                Log::info('Symfony API Response', ['data' => $data]);
//
//                return $data;
//            }
//
//            // Log des erreurs HTTP
//            Log::error('Symfony API Error', [
//                'status' => $response->status(),
//                'body' => $response->body()
//            ]);
//
//            return null;
//
//        } catch (\Exception $e) {
//            Log::error('Symfony API Exception', [
//                'message' => $e->getMessage(),
//                'trace' => $e->getTraceAsString()
//            ]);
//
//            throw $e;
//        }
//    }
//
//    /**
//     * Informations système Admin
//     */
////    public function getAdminSystem(): ?array
////    {
////        return $this->makeRequest('/admin/api/system');
////    }
//
//    /**
//     * Permissions Admin
//     */
//    public function getAdminPermissions(): ?array
//    {
//        return $this->makeRequest('/admin/api/permissions');
//    }
//
//    /**
//     * Dashboard Manager
//     */
//    public function getManagerDashboard(): ?array
//    {
//        return $this->makeRequest('/manager/api/dashboard');
//    }
//
//    /**
//     * Rapports Manager
//     */
//    public function getManagerReports(array $filters = []): ?array
//    {
//        return $this->makeRequest('/manager/api/reports', ['query' => $filters]);
//    }
//
//    /**
//     * Équipe Manager
//     */
//    public function getManagerTeam(): ?array
//    {
//        return $this->makeRequest('/manager/api/team');
//    }
//
//    /**
//     * Test de connectivité complet
//     */
//    public function testConnection(): array
//    {
//        $results = [];
//
//        // Test de connectivité de base
//        $results['basic_connection'] = $this->checkApiHealth();
//
//        // Test d'authentification
//        if ($results['basic_connection']) {
//            $authTest = $this->testAuthenticatedConnection();
//            $results['authenticated_connection'] = $authTest['success'];
//            $results['auth_details'] = $authTest;
//        }
//
//        // Informations sur la configuration
//        $results['config'] = [
//            'base_url' => $this->baseUrl,
//            'timeout' => $this->timeout,
//            'has_auth_token' => !is_null($this->getValidAuthToken())
//        ];
//
//        return $results;
//    }
//}




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

        // Vérifier que la configuration existe
        $baseUrl = config('services.symfony.base_url');
        if (empty($baseUrl)) {
            throw new \Exception('Configuration services.symfony.base_url manquante');
        }

        $this->symfonyBaseUrl = $baseUrl;
    }

    /**
     * Log sécurisé pour éviter les problèmes JSON
     */
    private function safeLog(string $level, string $message, array $context = []): void
    {
        // Nettoyer le contexte pour éviter les caractères problématiques
        $safeContext = array_map(function ($value) {
            if (is_string($value)) {
                // Supprimer les caractères de contrôle et limiter la longueur
                $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value);
                return mb_substr($value, 0, 100, 'UTF-8') . (mb_strlen($value) > 100 ? '...' : '');
            }
            return $value;
        }, $context);

        Log::log($level, $message, $safeContext);
    }

    /**
     * Méthode helper pour valider l'utilisateur et son token
     */
    private function validateUserAndToken(): ?object
    {
        if (!Auth::check()) {
            $this->safeLog('error', 'Utilisateur non authentifie');
            return null;
        }

        $user = Auth::user();

        if (!method_exists($user, 'hasValidKeycloakToken') || !$user->hasValidKeycloakToken()) {
            if (!method_exists($user, 'refreshKeycloakTokenIfNeeded') || !$user->refreshKeycloakTokenIfNeeded()) {
                $this->safeLog('error', 'Impossible de rafraichir le token Keycloak', [
                    'user_id' => $user->id ?? 'unknown'
                ]);
                return null;
            }
        }

        return $user;
    }

    /**
     * Récupérer les données du dashboard admin
     */
    public function getAdminDashboard(): ?array
    {
        $user = $this->validateUserAndToken();
        if (!$user) {
            return null;
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
        $user = $this->validateUserAndToken();
        if (!$user) {
            return null;
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/test/free',
            [],
            'GET'
        );
    }

    /**
     * Récupérer les informations système
     */
    public function getAdminSystem(): ?array
    {
        $user = $this->validateUserAndToken();
        if (!$user) {
            return null;
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            '/test/system',
            [],
            'GET'
        );
    }

    /**
     * Méthode générique pour appeler l'API Symfony
     */
    public function callApi(string $endpoint, array $data = [], string $method = 'GET'): ?array
    {
        $user = $this->validateUserAndToken();
        if (!$user) {
            return null;
        }

        return $this->tokenExchangeService->callSymfonyApi(
            $user->keycloak_token,
            $endpoint,
            $data,
            $method
        );
    }
}
