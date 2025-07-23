<?php

namespace App\Security;

use App\Service\KeycloakTokenValidatorService;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Psr\Log\LoggerInterface;

class KeycloakUserProvider implements UserProviderInterface
{
    private KeycloakTokenValidatorService $tokenValidator;
    private LoggerInterface $logger;

    public function __construct(
        KeycloakTokenValidatorService $tokenValidator,
        LoggerInterface $logger
    ) {
        $this->tokenValidator = $tokenValidator;
        $this->logger = $logger;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        // This will be called by the authenticator with the validated token data
        // For now, we'll throw an exception since we handle users in the authenticator
        throw new UserNotFoundException('User provider is handled by authenticator');
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        // For stateless authentication, we don't need to refresh users
        if (!$user instanceof InMemoryUser) {
            throw new UnsupportedUserException('User class not supported');
        }

        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return InMemoryUser::class === $class;
    }

    /**
     * Create a user from validated token data
     */
    public function createUserFromTokenData(array $validatedToken): UserInterface
    {
        $roles = $this->mapKeycloakRolesToSymfony($validatedToken);
        $userIdentifier = $validatedToken['username'] ?? $validatedToken['email'] ?? 'unknown';

        $this->logger->info('KeycloakUserProvider: Creating user from token', [
            'user_identifier' => $userIdentifier,
            'roles' => $roles
        ]);

        return new InMemoryUser($userIdentifier, null, $roles);
    }

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

        return array_unique($roles);
    }
}
