<?php

namespace App\Http\Controllers;

use App\Services\SymfonyApiService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class DebugController extends Controller
{
    private SymfonyApiService $symfonyApi;

    public function __construct(SymfonyApiService $symfonyApi)
    {
        $this->symfonyApi = $symfonyApi;
    }

    /**
     * Test de connectivité avec Symfony
     */
    public function testSymfonyConnection(): JsonResponse
    {
        $result = $this->symfonyApi->testConnection();

        return response()->json([
            'symfony_connection' => $result,
            'timestamp' => now()->toISOString()
        ]);
    }

    /**
     * Test des routes admin Symfony
     */
    public function testAdminRoutes(): JsonResponse
    {
        $results = $this->symfonyApi->testAdminRoutes();

        return response()->json([
            'admin_routes_test' => $results,
            'user_authenticated' => auth()->check(),
            'user_token_present' => !empty(session('keycloak_access_token')),
            'timestamp' => now()->toISOString()
        ]);
    }

    /**
     * Afficher les informations de configuration
     */
    public function showConfig(): JsonResponse
    {
        return response()->json([
            'config' => [
                'symfony_base_url' => config('services.symfony.base_url', 'non configuré'),
                'keycloak_base_url' => config('services.keycloak.base_url', 'non configuré'),
                'app_url' => config('app.url'),
            ],
            'session' => [
                'keycloak_token_present' => !empty(session('keycloak_access_token')),
                'user_authenticated' => auth()->check(),
            ],
            'user' => auth()->check() ? [
                'id' => auth()->user()->id,
                'name' => auth()->user()->name,
                'email' => auth()->user()->email,
                'roles' => auth()->user()->roles ?? [],
            ] : null
        ]);
    }

    /**
     * Test direct avec token manuel
     */
    public function testWithManualToken(Request $request): JsonResponse
    {
        $token = $request->input('token');

        if (!$token) {
            return response()->json(['error' => 'Token requis'], 400);
        }

        try {
            $response = \Illuminate\Support\Facades\Http::withHeaders([
                'Authorization' => 'Bearer ' . $token,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json'
            ])->timeout(10)->get('http://localhost:8003/admin/api/dashboard');

            Log::info('Test manuel avec token', [
                'token_provided' => !empty($token),
                'response_status' => $response->status(),
                'response_body' => $response->body()
            ]);

            return response()->json([
                'status' => $response->status(),
                'successful' => $response->successful(),
                'body' => $response->body(),
                'headers' => $response->headers()
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'token_provided' => !empty($token)
            ], 500);
        }
    }

    /**
     * Vérifier les routes Symfony disponibles
     */
    public function checkSymfonyRoutes(): JsonResponse
    {
        $routes = [
            '/' => 'GET',
            '/admin' => 'GET',
            '/admin/api/dashboard' => 'GET',
            '/manager' => 'GET',
            '/manager/api/dashboard' => 'GET',
            '/login' => 'GET'
        ];

        $results = [];

        foreach ($routes as $route => $method) {
            try {
                $response = \Illuminate\Support\Facades\Http::timeout(5)->get('http://localhost:8003' . $route);

                $results[$route] = [
                    'status' => $response->status(),
                    'accessible' => $response->status() !== 404,
                    'redirect_to_login' => str_contains($response->body(), 'Redirecting to /login'),
                    'content_preview' => substr(strip_tags($response->body()), 0, 100)
                ];

            } catch (\Exception $e) {
                $results[$route] = [
                    'status' => 'error',
                    'error' => $e->getMessage()
                ];
            }
        }

        return response()->json([
            'symfony_routes_check' => $results,
            'base_url' => 'http://localhost:8003'
        ]);
    }
}
