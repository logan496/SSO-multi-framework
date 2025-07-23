<?php

namespace App\Http\Controllers;

use App\Services\SymfonyApiService;
use App\Services\KeycloakService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;

class ManagerDashboardController extends Controller
{
    private SymfonyApiService $symfonyApi;
    private KeycloakService $keycloakService;

    public function __construct(SymfonyApiService $symfonyApi, KeycloakService $keycloakService)
    {
        $this->symfonyApi = $symfonyApi;
        $this->keycloakService = $keycloakService;

        // Middleware pour vérifier que l'utilisateur est manager ou admin
//        $this->middleware(['auth', 'role:manager,admin']);
    }

    /**
     * Afficher le dashboard manager
     */
    public function dashboard(Request $request): JsonResponse
    {
        try {
            // Récupérer les données du dashboard manager depuis Symfony
            $dashboardData = $this->symfonyApi->getManagerDashboard();

            if (!$dashboardData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les données du dashboard manager',
                    'error' => 'API Symfony non accessible'
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $dashboardData,
                'message' => 'Dashboard manager récupéré avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur dashboard manager: ' . $e->getMessage(), [
                'user_id' => auth()->id(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération du dashboard manager',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Récupérer les rapports manager
     */
    public function reports(Request $request): JsonResponse
    {
        try {
            // Paramètres optionnels pour filtrer les rapports
            $filters = $request->only(['date_start', 'date_end', 'type']);

            $reportsData = $this->symfonyApi->getManagerReports($filters);

            if (!$reportsData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les rapports',
                ], 503);
            }

            // Ajouter des informations contextuelles Laravel
            $laravelStats = [
                'request_time' => now()->toDateTimeString(),
                'user' => [
                    'id' => auth()->id(),
                    'email' => auth()->user()->email,
                    'roles' => auth()->user()->roles ?? [],
                ],
                'filters_applied' => !empty($filters) ? $filters : null,
            ];

            return response()->json([
                'success' => true,
                'data' => [
                    'reports' => $reportsData,
                    'meta' => $laravelStats,
                ],
                'message' => 'Rapports récupérés avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur récupération rapports manager: ' . $e->getMessage(), [
                'user_id' => auth()->id(),
                'filters' => $request->only(['date_start', 'date_end', 'type'])
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération des rapports',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }

    /**
     * Récupérer l'équipe
     */
    public function team(Request $request): JsonResponse
    {
        try {
            $teamData = $this->symfonyApi->getManagerTeam();

            if (!$teamData) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer la team'
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $teamData,
                'message' => 'Team récupérée avec succès'
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur récupération de la team: ' . $e->getMessage(), [
                'user_id' => auth()->id()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la récupération de la team',
                'error' => config('app.debug') ? $e->getMessage() : 'Erreur interne'
            ], 500);
        }
    }
}
