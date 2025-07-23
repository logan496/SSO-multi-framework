<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\KeycloakService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Psr\Log\LoggerInterface;

#[Route('/test')]
class FreeController extends AbstractController
{
    private UserRepository $userRepository;
    private KeycloakService $keycloakService;
    private TokenStorageInterface $tokenStorage;
    private LoggerInterface $logger;

    public function __construct(
        UserRepository        $userRepository,
        KeycloakService       $keycloakService,
        TokenStorageInterface $tokenStorage,
        LoggerInterface       $logger
    )
    {
        $this->userRepository = $userRepository;
        $this->keycloakService = $keycloakService;
        $this->tokenStorage = $tokenStorage;
        $this->logger = $logger;
    }

    #[Route('/free', name: 'free', methods: ['GET'])]
    public function getUserData(Request $request): JsonResponse
    {
        $this->logger->info("requête reçue");

        // Debug: Log current authentication state
        $this->logAuthenticationDebugInfo();

        // Vérification du token Keycloak via le système d'authentification
        if (!$this->isAuthenticated()) {
            $this->logger->info("pas authentifier");
            return $this->createUnauthorizedResponse('Token manquant ou invalide');
        }

        // Vérifier les permissions admin
        if (!$this->isGranted('ROLE_ADMIN') && !$this->isGranted('ROLE_MANAGER')) {
            return $this->createForbiddenResponse('Permissions administrateur requises');
        }

        try {
            $users = $this->userRepository->findAll();
            $userStats = [
                'total' => count($users),
                'admins' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()))),
                'managers' => count(array_filter($users, fn($u) => in_array('ROLE_MANAGER', $u->getRoles()))),
                'users' => count(array_filter($users, fn($u) => !in_array('ROLE_ADMIN', $u->getRoles()) && !in_array('ROLE_MANAGER', $u->getRoles())))
            ];

            // Récupérer les infos utilisateur selon le type d'auth
            $userInfo = $this->getCurrentUserInfo();
            $authType = $this->getAuthenticationType();

            // Log de l'accès réussi
            $this->logger->info('Accès getUserData réussi', [
                'user_id' => $userInfo['sub'] ?? $userInfo['id'] ?? 'unknown',
                'email' => $userInfo['email'] ?? 'unknown',
                'auth_type' => $authType,
                'endpoint' => '/test/free'
            ]);

            return new JsonResponse([
                'success' => true,
                'data' => [
                    'users' => array_map([$this, 'serializeUser'], $users),
                    'stats' => $userStats,
                    'timestamp' => new \DateTime(),
                    'requested_by' => $userInfo['email'] ?? 'unknown',
                    'auth_type' => $authType
                ]
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Erreur dans getUserData', [
                'error' => $e->getMessage(),
                'user_id' => $this->getCurrentUserInfo()['sub'] ?? 'unknown'
            ]);

            return new JsonResponse([
                'success' => false,
                'message' => 'Internal server error',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/system', name: 'system', methods: ['GET'])]
    public function getSystemData(Request $request): JsonResponse
    {
        // Vérification du token Keycloak
        if (!$this->isAuthenticated()) {
            return $this->createUnauthorizedResponse('Token manquant ou invalide');
        }

        // Vérifier les permissions admin
        if (!$this->isGranted('ROLE_ADMIN') && !$this->isGranted('ROLE_MANAGER')) {
            return $this->createForbiddenResponse('Permissions administrateur requises');
        }

        try {
            $systemInfo = [
                'php_version' => PHP_VERSION,
                'symfony_version' => Kernel::VERSION,
                'server_time' => date('Y-m-d H:i:s'),
                'memory_usage' => round(memory_get_usage() / 1024 / 1024, 2) . 'MB',
                'memory_limit' => ini_get('memory_limit'),
                'keycloak_status' => $this->keycloakService->checkConnection(),
            ];

            $userInfo = $this->getCurrentUserInfo();
            $authType = $this->getAuthenticationType();

            // Log de l'accès réussi
            $this->logger->info('Accès getSystemData réussi', [
                'user_id' => $userInfo['sub'] ?? $userInfo['id'] ?? 'unknown',
                'email' => $userInfo['email'] ?? 'unknown',
                'auth_type' => $authType,
                'endpoint' => '/test/system'
            ]);

            return new JsonResponse([
                'success' => true,
                'data' => [
                    'systemInfo' => $systemInfo,
                    'requested_by' => $userInfo['email'] ?? 'unknown',
                    'auth_type' => $authType,
                    'timestamp' => new \DateTime()
                ]
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Erreur dans getSystemData', [
                'error' => $e->getMessage(),
                'user_id' => $this->getCurrentUserInfo()['sub'] ?? 'unknown'
            ]);

            return new JsonResponse([
                'success' => false,
                'message' => 'Internal server error',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/health', name: 'health_check', methods: ['GET'])]
    public function healthCheck(): JsonResponse
    {
        // Le health check reste public
        return new JsonResponse([
            'status' => 'ok',
            'timestamp' => new \DateTime(),
            'service' => 'symfony-api'
        ]);
    }

    #[Route('/profile', name: 'user_profile', methods: ['GET'])]
    public function getUserProfile(): JsonResponse
    {
        if (!$this->isAuthenticated()) {
            return $this->createUnauthorizedResponse('Token manquant ou invalide');
        }

        try {
            $userInfo = $this->getCurrentUserInfo();
            $authType = $this->getAuthenticationType();
            $keycloakToken = $this->getCurrentKeycloakToken();

            // Obtenir des infos additionnelles depuis Keycloak si nécessaire
            $detailedUserInfo = null;
            if ($keycloakToken && $authType === 'oauth2') {
                $detailedUserInfo = $this->keycloakService->getUserInfo($keycloakToken);
            }

            return new JsonResponse([
                'success' => true,
                'data' => [
                    'user_info' => $userInfo,
                    'detailed_info' => $detailedUserInfo,
                    'roles' => $this->getUser() ? $this->getUser()->getRoles() : [],
                    'auth_type' => $authType,
                    'keycloak_roles' => $keycloakToken ? $this->keycloakService->getUserRoles($keycloakToken) : []
                ]
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Erreur dans getUserProfile', [
                'error' => $e->getMessage(),
                'user_id' => $this->getCurrentUserInfo()['sub'] ?? 'unknown'
            ]);

            return new JsonResponse([
                'success' => false,
                'message' => 'Internal server error',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Déterminer le type d'authentification utilisé
     */
    private function getAuthenticationType(): string
    {
        $token = $this->tokenStorage->getToken();

        if (!$token) {
            return 'none';
        }

        // Check for PostAuthenticationToken with Keycloak attributes
        if (method_exists($token, 'getAttribute')) {
            $keycloakUserInfo = $token->getAttribute('keycloak_user_info');
            if ($keycloakUserInfo) {
                return 'token'; // Authentification par token API
            }
        }

        // Vérifier s'il s'agit d'un token de l'API (PreAuthenticatedToken avec attributs Keycloak)
        if ($token instanceof \Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken) {
            $keycloakUserInfo = $token->getAttribute('keycloak_user_info');
            if ($keycloakUserInfo) {
                return 'token'; // Authentification par token API
            }
        }

        // Vérifier s'il s'agit d'un utilisateur de l'entité User (OAuth2)
        $user = $token->getUser();
        if ($user instanceof \App\Entity\User) {
            return 'oauth2'; // Authentification OAuth2 web
        }

        return 'unknown';
    }

    /**
     * Vérifier si l'utilisateur est authentifié via Keycloak
     */
    private function isAuthenticated(): bool
    {
        // Method 1: Check if we have a security token with a user
        $token = $this->tokenStorage->getToken();

        if (!$token) {
            $this->logger->debug('No security token found in token storage');
            return false;
        }

        $user = $token->getUser();
        if (!$user || $user === 'anon.') {
            $this->logger->debug('No authenticated user found in token', [
                'user' => $user,
                'token_class' => get_class($token)
            ]);
            return false;
        }

        // Method 2: Use Symfony's built-in authentication check
        if (!$this->isGranted('IS_AUTHENTICATED_FULLY') && !$this->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
            $this->logger->debug('User is not fully authenticated according to Symfony security');
            return false;
        }

        $this->logger->debug('User is authenticated', [
            'auth_type' => $this->getAuthenticationType(),
            'user_class' => get_class($user),
            'token_class' => get_class($token)
        ]);

        return true;
    }

    /**
     * Log authentication debug information
     */
    private function logAuthenticationDebugInfo(): void
    {
        $token = $this->tokenStorage->getToken();

        if ($token) {
            // Get available attributes safely
            $attributes = [];
            if (method_exists($token, 'getAttributes')) {
                $attributes = array_keys($token->getAttributes());
            }

            // Get roles safely
            $roles = [];
            if (method_exists($token, 'getRoleNames')) {
                $roles = $token->getRoleNames();
            }

            $this->logger->debug('Current security token info', [
                'token_class' => get_class($token),
                'user' => $token->getUser(),
                'user_class' => $token->getUser() ? get_class($token->getUser()) : null,
                'attributes' => $attributes,
                'roles' => $roles,
                'auth_type' => $this->getAuthenticationType()
            ]);
        } else {
            $this->logger->debug('No security token found');
        }

        // Also log Symfony's authentication state
        $this->logger->debug('Symfony authentication grants', [
            'IS_AUTHENTICATED_FULLY' => $this->isGranted('IS_AUTHENTICATED_FULLY'),
            'IS_AUTHENTICATED_REMEMBERED' => $this->isGranted('IS_AUTHENTICATED_REMEMBERED'),
            'IS_AUTHENTICATED_ANONYMOUSLY' => $this->isGranted('IS_AUTHENTICATED_ANONYMOUSLY')
        ]);
    }

    /**
     * Obtenir les informations utilisateur depuis le token
     */
    private function getCurrentUserInfo(): array
    {
        $token = $this->tokenStorage->getToken();

        if (!$token) {
            return [];
        }

        $user = $token->getUser();

        // First check for PostAuthenticationToken with Keycloak attributes
        if (method_exists($token, 'getAttribute')) {
            $keycloakUserInfo = $token->getAttribute('keycloak_user_info');
            if ($keycloakUserInfo) {
                return $keycloakUserInfo;
            }
        }

        // Cas 1: Authentification par token API (PreAuthenticatedToken avec attributs Keycloak)
        if ($token instanceof \Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken) {
            $keycloakUserInfo = $token->getAttribute('keycloak_user_info');
            if ($keycloakUserInfo) {
                return $keycloakUserInfo;
            }
        }

        // Cas 2: Authentification OAuth2 (entité User)
        if ($user instanceof \App\Entity\User) {
            return [
                'id' => $user->getId(),
                'sub' => $user->getKeycloakId(),
                'email' => $user->getEmail(),
                'username' => $user->getUserIdentifier(),
                'name' => $user->getName()
            ];
        }

        // Fallback: try to get info from the User object
        if ($user && method_exists($user, 'getUserIdentifier')) {
            return [
                'sub' => method_exists($user, 'getId') ? $user->getId() : null,
                'email' => method_exists($user, 'getEmail') ? $user->getEmail() : $user->getUserIdentifier(),
                'preferred_username' => $user->getUserIdentifier()
            ];
        }

        return [];
    }

    /**
     * Obtenir le token Keycloak actuel
     */
    private function getCurrentKeycloakToken(): ?string
    {
        $token = $this->tokenStorage->getToken();

        if (!$token) {
            return null;
        }

        // Check if token has getAttribute method (works for both PostAuthenticationToken and PreAuthenticatedToken)
        if (method_exists($token, 'getAttribute')) {
            $keycloakToken = $token->getAttribute('keycloak_raw_token');
            if ($keycloakToken) {
                return $keycloakToken;
            }

            // Fallback to old attribute name
            $keycloakToken = $token->getAttribute('keycloak_token');
            if ($keycloakToken) {
                return $keycloakToken;
            }
        }

        // Pour l'authentification OAuth2, vous pourriez avoir le token stocké différemment
        // Cela dépend de votre implémentation OAuth2
        return null;
    }

    /**
     * Créer une réponse d'erreur 401
     */
    private function createUnauthorizedResponse(string $message): JsonResponse
    {
        return new JsonResponse([
            'success' => false,
            'message' => $message,
            'code' => 401
        ], 401);
    }

    /**
     * Créer une réponse d'erreur 403
     */
    private function createForbiddenResponse(string $message): JsonResponse
    {
        return new JsonResponse([
            'success' => false,
            'message' => $message,
            'code' => 403
        ]);
    }

    /**
     * Sérialiser un utilisateur pour la réponse JSON
     */
    private function serializeUser($user): array
    {
        if (!$user) return [];

        return [
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'username' => $user->getUserIdentifier(),
            'roles' => $user->getRoles(),
            'keycloak_id' => $user->getKeycloakId() ?? null,
        ];
    }
}
