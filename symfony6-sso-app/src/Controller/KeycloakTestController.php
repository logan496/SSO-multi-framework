<?php

namespace App\Controller;

use App\Service\KeycloakTokenValidatorService;
use App\Service\KeycloakService;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/keycloak')]
class KeycloakTestController extends AbstractController
{
    private KeycloakTokenValidatorService $tokenValidator;
    private KeycloakService $keycloakService;
    private LoggerInterface $logger;

    public function __construct(
        KeycloakTokenValidatorService $tokenValidator,
        KeycloakService $keycloakService,
        LoggerInterface $logger
    ) {
        $this->tokenValidator = $tokenValidator;
        $this->keycloakService = $keycloakService;
        $this->logger = $logger;
    }

    #[Route('/test-config', name: 'keycloak_test_config', methods: ['GET'])]
    public function testConfiguration(): JsonResponse
    {
        try {
            $config = $this->tokenValidator->getKeycloakConfiguration();

            return new JsonResponse([
                'success' => true,
                'message' => 'Configuration Keycloak',
                'data' => $config
            ]);
        } catch (\Exception $e) {
            return new JsonResponse([
                'success' => false,
                'message' => 'Erreur lors de la récupération de la configuration',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/test-token', name: 'keycloak_test_token', methods: ['POST'])]
    public function testToken(Request $request): JsonResponse
    {
        try {
            $authHeader = $request->headers->get('Authorization');

            if (!$authHeader) {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Header Authorization manquant'
                ], 400);
            }

            $token = $this->tokenValidator->extractBearerToken($authHeader);

            if (!$token) {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Token Bearer invalide'
                ], 400);
            }

            $this->logger->info('Testing token validation', [
                'token_length' => strlen($token)
            ]);

            // Test de validation du token
            $validationResult = $this->tokenValidator->validateExchangedToken($token);

            if ($validationResult) {
                return new JsonResponse([
                    'success' => true,
                    'message' => 'Token validé avec succès',
                    'data' => $validationResult
                ]);
            } else {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Token invalide ou expiré'
                ], 401);
            }

        } catch (\Exception $e) {
            $this->logger->error('Erreur lors du test de token', [
                'error' => $e->getMessage()
            ]);

            return new JsonResponse([
                'success' => false,
                'message' => 'Erreur lors de la validation du token',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/test-connection', name: 'keycloak_test_connection', methods: ['GET'])]
    public function testConnection(): JsonResponse
    {
        try {
            $status = $this->keycloakService->checkConnection();

            return new JsonResponse([
                'success' => true,
                'message' => 'Test de connexion Keycloak',
                'data' => [
                    'keycloak_status' => $status,
                    'timestamp' => new \DateTime()
                ]
            ]);
        } catch (\Exception $e) {
            return new JsonResponse([
                'success' => false,
                'message' => 'Erreur lors du test de connexion',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/decode-token', name: 'keycloak_decode_token', methods: ['POST'])]
    public function decodeToken(Request $request): JsonResponse
    {
        try {
            $authHeader = $request->headers->get('Authorization');

            if (!$authHeader) {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Header Authorization manquant'
                ], 400);
            }

            $token = $this->tokenValidator->extractBearerToken($authHeader);

            if (!$token) {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Token Bearer invalide'
                ], 400);
            }

            // Décoder le token sans validation
            $userInfo = $this->keycloakService->decodeToken($token);

            if ($userInfo) {
                return new JsonResponse([
                    'success' => true,
                    'message' => 'Token décodé avec succès',
                    'data' => $userInfo
                ]);
            } else {
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Impossible de décoder le token'
                ], 400);
            }

        } catch (\Exception $e) {
            return new JsonResponse([
                'success' => false,
                'message' => 'Erreur lors du décodage du token',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}
