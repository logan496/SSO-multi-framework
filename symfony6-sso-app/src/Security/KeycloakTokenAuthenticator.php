<?php

namespace App\Security;

use App\Service\KeycloakTokenValidatorService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Psr\Log\LoggerInterface;

class KeycloakTokenAuthenticator extends AbstractAuthenticator
{
    private KeycloakTokenValidatorService $tokenValidator;
    private KeycloakUserProvider $userProvider;
    private LoggerInterface $logger;

    public function __construct(
        KeycloakTokenValidatorService $tokenValidator,
        KeycloakUserProvider $userProvider,
        LoggerInterface $logger
    ) {
        $this->tokenValidator = $tokenValidator;
        $this->userProvider = $userProvider;
        $this->logger = $logger;
    }

    public function supports(Request $request): ?bool
    {
        // Skip authentication for public routes
        if ($this->isPublicRoute($request->getPathInfo())) {
            $this->logger->debug('KeycloakAuthenticator: Skipping public route', [
                'path' => $request->getPathInfo()
            ]);
            return false;
        }

        // Only support requests with Authorization header
        $hasAuth = $request->headers->has('Authorization');

        $this->logger->debug('KeycloakAuthenticator: Checking support', [
            'path' => $request->getPathInfo(),
            'has_auth_header' => $hasAuth,
            'auth_preview' => $hasAuth ? substr($request->headers->get('Authorization'), 0, 20) . '...' : 'none'
        ]);

        return $hasAuth;
    }

    public function authenticate(Request $request): Passport
    {
        $this->logger->info('KeycloakAuthenticator: Starting authentication');

        $authHeader = $request->headers->get('Authorization');

        if (!$authHeader) {
            throw new CustomUserMessageAuthenticationException('No Authorization header found');
        }

        $token = $this->tokenValidator->extractBearerToken($authHeader);
        if (!$token) {
            throw new CustomUserMessageAuthenticationException('Invalid Authorization header format');
        }

        // Validate token
        $validatedToken = $this->tokenValidator->validateExchangedToken($token);
        if (!$validatedToken || !($validatedToken['valid'] ?? false)) {
            throw new CustomUserMessageAuthenticationException('Invalid or expired token');
        }

        $this->logger->info('KeycloakAuthenticator: Token validated successfully', [
            'user_id' => $validatedToken['user_id'],
            'username' => $validatedToken['username']
        ]);

        $userIdentifier = $validatedToken['username'] ?? $validatedToken['email'] ?? 'unknown';

        $passport = new SelfValidatingPassport(
            new UserBadge($userIdentifier, function () use ($validatedToken) {
                return $this->userProvider->createUserFromTokenData($validatedToken);
            })
        );

        // Store the validated token data for later use
        $passport->setAttribute('keycloak_validated_token', $validatedToken);
        $passport->setAttribute('keycloak_raw_token', $token);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        // Create the token normally
        $token = parent::createToken($passport, $firewallName);

        // Transfer passport attributes to the token
        $validatedToken = $passport->getAttribute('keycloak_validated_token');
        $rawToken = $passport->getAttribute('keycloak_raw_token');

        if ($validatedToken && method_exists($token, 'setAttribute')) {
            $token->setAttribute('keycloak_validated_token', $validatedToken);
            $token->setAttribute('keycloak_raw_token', $rawToken);
            $token->setAttribute('keycloak_user_info', [
                'sub' => $validatedToken['user_id'],
                'email' => $validatedToken['email'],
                'username' => $validatedToken['username'],
                'preferred_username' => $validatedToken['username'],
                'exp' => $validatedToken['expires_at'],
                'iat' => $validatedToken['issued_at'],
                'roles' => $validatedToken['roles'],
                'client_roles' => $validatedToken['client_roles']
            ]);

            $this->logger->info('KeycloakAuthenticator: Token attributes set successfully', [
                'user_id' => $validatedToken['user_id'],
                'username' => $validatedToken['username'],
                'roles_count' => count($validatedToken['roles'] ?? [])
            ]);
        }

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->logger->info('KeycloakAuthenticator: Authentication successful', [
            'user' => $token->getUserIdentifier(),
            'roles' => $token->getRoleNames(),
            'token_class' => get_class($token)
        ]);

        // Don't handle, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->logger->warning('KeycloakAuthenticator: Authentication failed', [
            'message' => $exception->getMessage(),
            'path' => $request->getPathInfo()
        ]);

        return new JsonResponse([
            'success' => false,
            'message' => 'Authentication failed: ' . $exception->getMessage(),
            'code' => 401
        ], 401);
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
}
