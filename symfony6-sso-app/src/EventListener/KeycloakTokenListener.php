<?php

namespace App\EventListener;

use App\Service\KeycloakTokenValidatorService;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\JsonResponse;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

// Priorité élevée pour s'exécuter avant le firewall Symfony
#[AsEventListener(event: KernelEvents::REQUEST, priority: 512)]
class KeycloakTokenListener
{
    private KeycloakTokenValidatorService $tokenValidator;
    private LoggerInterface $logger;
    private TokenStorageInterface $tokenStorage;

    public function __construct(
        KeycloakTokenValidatorService $tokenValidator,
        LoggerInterface $logger,
        TokenStorageInterface $tokenStorage
    ) {
        $this->tokenValidator = $tokenValidator;
        $this->logger = $logger;
        $this->tokenStorage = $tokenStorage;
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $path = $request->getPathInfo();

        // IMPORTANT: Seulement traiter les routes API et test
        if (!$this->isApiRoute($path)) {
            $this->logger->debug('KeycloakTokenListener: Skipping non-API route', [
                'path' => $path
            ]);
            return;
        }

        $this->logger->info('KeycloakTokenListener: Processing API route', [
            'path' => $path,
            'method' => $request->getMethod(),
            'route' => $request->attributes->get('_route'),
            'has_auth_header' => $request->headers->has('Authorization'),
        ]);

        // Skip authentication for public routes
        if ($this->isPublicRoute($path)) {
            $this->logger->info('KeycloakTokenListener: Skipping public route', [
                'path' => $path
            ]);
            return;
        }

        // Extract Authorization header
        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader) {
            $this->logger->warning('KeycloakTokenListener: No Authorization header found', [
                'path' => $path
            ]);
            return;
        }

        // Extract Bearer token
        $token = $this->tokenValidator->extractBearerToken($authHeader);
        if (!$token) {
            $this->logger->warning('KeycloakTokenListener: Invalid Authorization header format', [
                'auth_header_start' => substr($authHeader, 0, 20)
            ]);
            $this->setUnauthorizedResponse($event, 'Invalid authorization header format');
            return;
        }

        $this->logger->info('KeycloakTokenListener: Starting token validation', [
            'token_preview' => substr($token, 0, 20) . '...'
        ]);

        // Validate token
        $validatedToken = $this->tokenValidator->validateExchangedToken($token);
        if (!$validatedToken || !($validatedToken['valid'] ?? false)) {
            $this->logger->warning('KeycloakTokenListener: Token validation failed');
            $this->setUnauthorizedResponse($event, 'Invalid or expired token');
            return;
        }

        $this->logger->info('KeycloakTokenListener: Token validated successfully');

        // Create Symfony user with roles
        $roles = $this->mapKeycloakRolesToSymfony($validatedToken);
        $user = new InMemoryUser(
            $validatedToken['username'] ?? $validatedToken['email'] ?? 'unknown',
            null, // No password needed for token-based auth
            $roles
        );

        // Create Symfony security token
        $securityToken = new PreAuthenticatedToken(
            $user,
            'api', // Use 'api' firewall name
            $roles
        );

        // Store Keycloak-specific data as token attributes
        $securityToken->setAttribute('keycloak_token', $token);
        $securityToken->setAttribute('keycloak_user_info', [
            'sub' => $validatedToken['user_id'],
            'email' => $validatedToken['email'],
            'username' => $validatedToken['username'],
            'preferred_username' => $validatedToken['username'],
            'exp' => $validatedToken['expires_at'],
            'iat' => $validatedToken['issued_at'],
            'roles' => $validatedToken['roles'],
            'client_roles' => $validatedToken['client_roles']
        ]);

        // Store the token in Symfony's security system
        $this->tokenStorage->setToken($securityToken);

        $this->logger->info('KeycloakTokenListener: Security token stored successfully', [
            'token_class' => get_class($securityToken),
            'user_identifier' => $user->getUserIdentifier(),
            'roles_count' => count($roles),
            'keycloak_user_id' => $validatedToken['user_id'] ?? 'unknown',
            'firewall' => 'api'
        ]);

        $this->logger->info('KeycloakTokenListener: Authentication successful for API', [
            'email' => $validatedToken['email'],
            'roles' => $roles,
            'user_id' => $validatedToken['user_id'],
            'path' => $path
        ]);
    }

    /**
     * Check if the route is an API route that should use token authentication
     */
    private function isApiRoute(string $path): bool
    {
        $apiPaths = [
            '/api/',
            '/test/', // Vos routes de test utilisent aussi l'auth par token
        ];

        foreach ($apiPaths as $apiPath) {
            if (str_starts_with($path, $apiPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Map Keycloak roles to Symfony roles
     */
    private function mapKeycloakRolesToSymfony(array $validatedToken): array
    {
        $roles = ['ROLE_USER']; // Default role

        // Add realm roles
        $realmRoles = $validatedToken['roles'] ?? [];
        foreach ($realmRoles as $role) {
            $roles[] = 'ROLE_' . strtoupper($role);
        }

        // Add client roles
        $clientRoles = $validatedToken['client_roles'] ?? [];
        foreach ($clientRoles as $role) {
            $roles[] = 'ROLE_' . strtoupper($role);
        }

        // Remove duplicates and ensure ROLE_USER is always present
        $roles = array_unique($roles);

        $this->logger->debug('KeycloakTokenListener: Mapped roles', [
            'keycloak_realm_roles' => $realmRoles,
            'keycloak_client_roles' => $clientRoles,
            'symfony_roles' => $roles
        ]);

        return $roles;
    }

    /**
     * Check if the route is public (doesn't require authentication)
     */
    private function isPublicRoute(string $path): bool
    {
        $publicRoutes = [
            '/test/health',
            '/api/health',
            '/health',
            '/_profiler',
            '/_wdt'
        ];

        foreach ($publicRoutes as $publicRoute) {
            if (str_starts_with($path, $publicRoute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set unauthorized response and stop event propagation
     */
    private function setUnauthorizedResponse(RequestEvent $event, string $message): void
    {
        $this->logger->warning('KeycloakTokenListener: Setting unauthorized response', [
            'message' => $message
        ]);

        $response = new JsonResponse([
            'success' => false,
            'message' => $message,
            'code' => 401
        ], 401);

        $event->setResponse($response);
    }
}
