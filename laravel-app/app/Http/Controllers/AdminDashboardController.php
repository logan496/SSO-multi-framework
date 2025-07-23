<?php

namespace App\Http\Controllers;

use App\Services\SymfonyApiService;
use App\Services\KeycloakService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;

class AdminDashboardController extends Controller
{
    private SymfonyApiService $symfonyApi;
    private KeycloakService $keycloakService;

    public function __construct(SymfonyApiService $symfonyApi, KeycloakService $keycloakService)
    {
        $this->symfonyApi = $symfonyApi;
        $this->keycloakService = $keycloakService;

        // Middleware pour vérifier que l'utilisateur est admin
//        $this->middleware(['auth', 'role:admin']);
    }

    /**
     * Gérer les erreurs d'authentification avec Symfony
     */
    private function handleSymfonyAuthError(): JsonResponse
    {
        Log::warning('Erreur d\'authentification avec Symfony API', [
            'user_id' => auth()->id(),
            'user_email' => auth()->user()->email ?? null
        ]);

        return response()->json([
            'success' => false,
            'message' => 'Erreur d\'authentification avec l\'API backend',
            'error_code' => 'SYMFONY_AUTH_ERROR',
            'suggestions' => [
                'Vérifiez que votre session est toujours active',
                'Reconnectez-vous si nécessaire'
            ]
        ], 401);
    }

    /**
     * Afficher le dashboard admin
     */
    public function dashboard(Request $request): JsonResponse
    {
        try {

            if (!auth()->check()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Utilisateur non authentifier'
                ], 401);
            }
            // Récupérer les données du dashboard depuis Symfony
            $dashboardData = $this->symfonyApi->getAdminDashboard();

            if (!$dashboardData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les données du dashboard',
                    'error' => 'API Symfony non accessible'
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $dashboardData,
                'message' => 'Dashboard admin récupéré avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur dashboard admin: ' . $e->getMessage(), [
                'user_id' => auth()->id(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération du dashboard',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Récupérer la liste des utilisateurs
     */
    public function users(Request $request): JsonResponse
    {
        try {
            $usersData = $this->symfonyApi->getAllUsers();

            if (!$usersData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer la liste des utilisateurs',
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $usersData,
                'message' => 'Liste des utilisateurs récupérée avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur récupération utilisateurs admin: ' . $e->getMessage(), [
                'user_id' => auth()->id()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération des utilisateurs',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Récupérer les informations système
     */
    public function system(Request $request): JsonResponse
    {
        try {
            $systemData = $this->symfonyApi->getAdminSystem();

            if (!$systemData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les informations système',
                ], 503);
            }

            // Ajouter des informations Laravel
            $laravelSystemInfo = [
                'laravel_version' => app()->version(),
                'php_version' => PHP_VERSION,
                'server_time' => now()->toDateTimeString(),
                'memory_usage' => round(memory_get_usage() / 1024 / 1024, 2) . 'MB',
                'memory_limit' => ini_get('memory_limit'),
                'environment' => config('app.env'),
            ];

            return response()->json([
                'success' => true,
                'data' => [
                    'symfony' => $systemData,
                    'laravel' => $laravelSystemInfo,
                ],
                'message' => 'Informations système récupérées avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur récupération système admin: ' . $e->getMessage(), [
                'user_id' => auth()->id()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération des informations système',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Récupérer les permissions
     */
    public function permissions(Request $request): JsonResponse
    {
        try {
            $permissionsData = $this->symfonyApi->getAdminPermissions();

            if (!$permissionsData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les permissions',
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $permissionsData,
                'message' => 'Permissions récupérées avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur récupération permissions admin: ' . $e->getMessage(), [
                'user_id' => auth()->id()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération des permissions',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }


    /**
     * Vérifier le statut de l'API Symfony
     */
    public function apiStatus(Request $request): JsonResponse
    {
        try {
            $isHealthy = $this->symfonyApi->checkApiHealth();
            $keycloakStatus = $this->keycloakService->checkConnection();

            return response()->json([
                'success' => true,
                'data' => [
                    'symfony_api' => [
                        'status' => $isHealthy ? 'healthy' : 'unhealthy',
                        'accessible' => $isHealthy,
                    ],
                    'keycloak' => $keycloakStatus,
                    'laravel' => [
                        'status' => 'healthy',
                        'version' => app()->version(),
                        'environment' => config('app.env'),
                    ]
                ],
                'message' => 'Statut des services récupéré'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur vérification statut API: ' . $e->getMessage());

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la vérification du statut',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }
}
