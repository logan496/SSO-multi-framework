<?php

namespace App\Http\Controllers;

use App\Services\KeycloakService;
use App\Services\SymfonyApiService;
use Illuminate\Http\JsonResponse;

class FreeController extends Controller
{

    private KeycloakService $keycloakService;
    private SymfonyApiService $symfonyApi;

    public function __construct(SymfonyApiService $symfonyApi, KeycloakService $keycloakService) {
        $this->symfonyApi = $symfonyApi;
        $this->keycloakService = $keycloakService;
    }

    public function test(): JsonResponse {
        try{

            $userData = $this->symfonyApi->getAllUsers();

            if (!$userData) {
                return response()->json([
                    'success' => false,
                    'message' => 'No data found',
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $userData,
                'message' => 'All data found',

            ]);
        } catch (\Exception $exception) {
            return response()->json([
                'success' => false,
                'message' => $exception->getMessage(),
            ], 500);
        }
    }

    public function takeAdminSystem(): JsonResponse {
        try{
            $userData = $this->symfonyApi->getAdminSystem();

            if (!$userData) {
                return response()->json([
                    'success' => false,
                    'message' => 'No data found',
                ], 503);
            }

            return response()->json([
                'success' => true,
                'data' => $userData,
                'message' => 'All data found',

            ]);
        } catch (\Exception $exception) {
            return response()->json([
                'success' => false,
                'message' => $exception->getMessage(),
            ], 500);
        }
    }

}
