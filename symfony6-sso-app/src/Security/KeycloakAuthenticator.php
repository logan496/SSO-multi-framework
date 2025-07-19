<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Psr\Log\LoggerInterface;

class KeycloakAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public function __construct(
        private ClientRegistry         $clientRegistry,
        private RouterInterface        $router,
        private UserRepository         $userRepository,
        private EntityManagerInterface $entityManager,
        private ?LoggerInterface       $logger = null
    )
    {
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'connect_keycloak_check';
    }

    /**
     * @throws IdentityProviderException
     */
    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('keycloak');
        $accessToken = $this->fetchAccessToken($client);

        // Debug complet du token
        $this->debugCompleteToken($accessToken);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {
                /** @var Keycloak $provider */
                $provider = $client->getOAuth2Provider();
                $keycloakUser = $provider->getResourceOwner($accessToken);

                // Log des informations de debug
                $this->logger?->info('Keycloak user data', [
                    'id' => $keycloakUser->getId(),
                    'email' => $keycloakUser->getEmail(),
                    'name' => $keycloakUser->getName(),
                ]);

                // Extraire les rôles depuis le token
                $keycloakRoles = $this->extractRolesFromToken($accessToken);

                $this->logger?->info('Final extracted roles for authentication', [
                    'roles' => $keycloakRoles,
                    'count' => count($keycloakRoles)
                ]);

                // Chercher l'utilisateur existant
                $existingUser = $this->userRepository->findOneBy(['keycloakId' => $keycloakUser->getId()]);

                if ($existingUser) {
                    // IMPORTANT: Mettre à jour les rôles à chaque connexion
                    $this->logger?->info('Updating existing user roles', [
                        'user_id' => $existingUser->getId(),
                        'old_roles' => $existingUser->getRoles(),
                        'new_roles' => $keycloakRoles
                    ]);

                    $existingUser->setRoles($keycloakRoles);
                    $existingUser->setEmail($keycloakUser->getEmail());
                    $existingUser->setName($keycloakUser->getName() ?? $keycloakUser->getPreferredUsername());
                    $existingUser->setUpdatedAt(new \DateTimeImmutable());

                    $this->entityManager->flush();

                    $this->logger?->info('User roles updated successfully', [
                        'user_id' => $existingUser->getId(),
                        'final_roles' => $existingUser->getRoles()
                    ]);

                    return $existingUser;
                }

                // Créer un nouvel utilisateur
                $user = new User();
                $user->setKeycloakId($keycloakUser->getId());
                $user->setEmail($keycloakUser->getEmail());
                $user->setName($keycloakUser->getName() ?? $keycloakUser->getPreferredUsername());
                $user->setRoles($keycloakRoles);

                $this->entityManager->persist($user);
                $this->entityManager->flush();

                $this->logger?->info('Created new user with roles', [
                    'keycloak_id' => $user->getKeycloakId(),
                    'email' => $user->getEmail(),
                    'roles' => $user->getRoles()
                ]);

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $user = $token->getUser();

        $this->logger?->info('Authentication success - checking roles for redirect', [
            'user_id' => $user->getId(),
            'roles' => $user->getRoles(),
            'has_admin' => in_array('ROLE_ADMIN', $user->getRoles()),
            'has_manager' => in_array('ROLE_MANAGER', $user->getRoles())
        ]);

        // Redirection basée sur le rôle
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            $this->logger?->info('Redirecting to admin dashboard');
            return new RedirectResponse($this->router->generate('admin_dashboard'));
        } elseif (in_array('ROLE_MANAGER', $user->getRoles())) {
            $this->logger?->info('Redirecting to manager dashboard');
            return new RedirectResponse($this->router->generate('manager_dashboard'));
        }

        $this->logger?->info('Redirecting to default dashboard');
        return new RedirectResponse($this->router->generate('app_dashboard'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->logger?->error('Authentication failure', [
            'exception' => $exception->getMessage()
        ]);

        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @throws IdentityProviderException
     */
    private function fetchAccessToken(OAuth2ClientInterface $client): AccessToken
    {
        return $client->getAccessToken();
    }

    private function extractRolesFromToken(AccessToken $accessToken): array
    {
        try {
            $payload = $this->decodeJwtPayload($accessToken->getToken());

            if (!$payload) {
                $this->logger?->error('Failed to decode JWT payload');
                return ['ROLE_USER'];
            }

            // LOG COMPLET DU PAYLOAD pour debug
            $this->logger?->info('JWT Payload analysis', [
                'has_resource_access' => isset($payload['resource_access']),
                'has_realm_access' => isset($payload['realm_access']),
                'has_groups' => isset($payload['groups']),
                'email' => $payload['email'] ?? 'not found',
                'preferred_username' => $payload['preferred_username'] ?? 'not found'
            ]);

            $roles = [];

            // 1. Rôles depuis resource_access (priorité haute)
            if (isset($payload['resource_access'])) {
                $this->logger?->info('Analyzing resource_access', [
                    'clients' => array_keys($payload['resource_access'])
                ]);

                foreach ($payload['resource_access'] as $clientId => $clientData) {
                    if (isset($clientData['roles']) && is_array($clientData['roles'])) {
                        foreach ($clientData['roles'] as $role) {
                            $normalizedRole = $this->normalizeRole($role);
                            $roles[] = $normalizedRole;
                            $this->logger?->info("Role found in resource_access", [
                                'client' => $clientId,
                                'original' => $role,
                                'normalized' => $normalizedRole
                            ]);
                        }
                    }
                }
            }

            // 2. Rôles depuis realm_access
            if (isset($payload['realm_access']['roles']) && is_array($payload['realm_access']['roles'])) {
                $this->logger?->info('Analyzing realm_access roles', [
                    'roles_count' => count($payload['realm_access']['roles'])
                ]);

                foreach ($payload['realm_access']['roles'] as $role) {
                    // Exclure les rôles système Keycloak
                    if (!in_array($role, ['default-roles-master', 'offline_access', 'uma_authorization', 'default-roles-realm'])) {
                        $normalizedRole = $this->normalizeRole($role);
                        $roles[] = $normalizedRole;
                        $this->logger?->info("Role found in realm_access", [
                            'original' => $role,
                            'normalized' => $normalizedRole
                        ]);
                    } else {
                        $this->logger?->debug("Skipping system role", ['role' => $role]);
                    }
                }
            }

            // 3. Rôles depuis les groupes
            if (isset($payload['groups']) && is_array($payload['groups'])) {
                $this->logger?->info('Analyzing groups', [
                    'groups_count' => count($payload['groups'])
                ]);

                foreach ($payload['groups'] as $group) {
                    $groupName = trim($group, '/');
                    if (!empty($groupName)) {
                        $normalizedRole = $this->normalizeRole($groupName);
                        $roles[] = $normalizedRole;
                        $this->logger?->info("Role found in groups", [
                            'original' => $group,
                            'group_name' => $groupName,
                            'normalized' => $normalizedRole
                        ]);
                    }
                }
            }

            // Nettoyer et dédupliquer les rôles
            $finalRoles = array_unique(array_filter($roles));

            // Si aucun rôle trouvé, utiliser le rôle par défaut
            if (empty($finalRoles)) {
                $finalRoles = ['ROLE_USER'];
                $this->logger?->warning('No roles found in token, using default ROLE_USER');
            }

            $this->logger?->info('Final roles extraction result', [
                'extracted_roles' => $finalRoles,
                'total_count' => count($finalRoles)
            ]);

            return $finalRoles;

        } catch (\Exception $e) {
            $this->logger?->error('Error extracting roles from token', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return ['ROLE_USER'];
        }
    }

    /**
     * Décode proprement le payload JWT
     */
    private function decodeJwtPayload(string $jwt): ?array
    {
        $tokenParts = explode('.', $jwt);

        if (count($tokenParts) !== 3) {
            $this->logger?->warning('Invalid JWT token format - expected 3 parts, got ' . count($tokenParts));
            return null;
        }

        try {
            // Décoder le payload (partie du milieu)
            $payload = $tokenParts[1];

            // Log pour debug
            $this->logger?->info('JWT decoding attempt', [
                'payload_length' => strlen($payload),
                'payload_sample' => substr($payload, 0, 50)
            ]);

            // Méthode 1: Décodage base64 URL-safe standard
            $decodedPayload = $this->base64UrlDecode($payload);

            if ($decodedPayload === false) {
                $this->logger?->error('Base64 URL decoding failed');
                return null;
            }

            // Vérifier si c'est du JSON valide
            if (!$this->isValidJson($decodedPayload)) {
                $this->logger?->error('Decoded payload is not valid JSON', [
                    'decoded_sample' => substr($decodedPayload, 0, 100),
                    'json_error' => json_last_error_msg()
                ]);
                return null;
            }

            $jsonData = json_decode($decodedPayload, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger?->error('JSON decode error', [
                    'error' => json_last_error_msg(),
                    'decoded_sample' => substr($decodedPayload, 0, 100)
                ]);
                return null;
            }

            return $jsonData;

        } catch (\Exception $e) {
            $this->logger?->error('Exception during JWT payload decoding', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return null;
        }
    }

    /**
     * Vérifie si une chaîne est du JSON valide
     */
    private function isValidJson(string $string): bool
    {
        json_decode($string);
        return json_last_error() === JSON_ERROR_NONE;
    }

    private function debugCompleteToken(AccessToken $accessToken): void
    {
        try {
            $payload = $this->decodeJwtPayload($accessToken->getToken());

            if ($payload) {
                // Log complet pour debug
                $this->logger?->info("=== COMPLETE TOKEN DEBUG ===", [
                    'email' => $payload['email'] ?? 'not found',
                    'preferred_username' => $payload['preferred_username'] ?? 'not found',
                    'sub' => $payload['sub'] ?? 'not found',
                    'iss' => $payload['iss'] ?? 'not found',
                    'aud' => $payload['aud'] ?? 'not found'
                ]);

                if (isset($payload['realm_access']['roles'])) {
                    $this->logger?->info("Realm roles found", [
                        'roles' => $payload['realm_access']['roles']
                    ]);
                } else {
                    $this->logger?->warning("No realm_access.roles found");
                }

                if (isset($payload['resource_access'])) {
                    foreach ($payload['resource_access'] as $clientId => $data) {
                        if (isset($data['roles'])) {
                            $this->logger?->info("Resource access roles found", [
                                'client' => $clientId,
                                'roles' => $data['roles']
                            ]);
                        }
                    }
                } else {
                    $this->logger?->warning("No resource_access found");
                }

                if (isset($payload['groups'])) {
                    $this->logger?->info("Groups found", [
                        'groups' => $payload['groups']
                    ]);
                } else {
                    $this->logger?->warning("No groups found");
                }

                // Sauvegarde complète du payload pour debug
                if ($this->logger) {
                    $debugFile = '/tmp/keycloak_debug_' . time() . '_' . ($payload['email'] ?? 'unknown') . '.json';
                    file_put_contents($debugFile, json_encode($payload, JSON_PRETTY_PRINT));
                    $this->logger->info("Full payload saved for debugging", ['file' => $debugFile]);
                }
            } else {
                $this->logger?->error("Could not decode token payload for debugging");
            }

        } catch (\Exception $e) {
            $this->logger?->error("Error debugging token", ['error' => $e->getMessage()]);
        }
    }

    /**
     * Normalise un rôle en format Symfony (ROLE_UPPERCASE)
     */
    private function normalizeRole(string $role): string
    {
        // Si le rôle commence déjà par ROLE_, le retourner en majuscules
        if (str_starts_with($role, 'ROLE_')) {
            return strtoupper($role);
        }

        // Mapping des rôles spécifiques
        $roleMapping = [
            'admin' => 'ROLE_ADMIN',
            'manager' => 'ROLE_MANAGER',
            'user' => 'ROLE_USER',
            'administrateur' => 'ROLE_ADMIN',
            'gestionnaire' => 'ROLE_MANAGER',
            'utilisateur' => 'ROLE_USER',
        ];

        $lowerRole = strtolower(trim($role));

        if (isset($roleMapping[$lowerRole])) {
            $this->logger?->debug("Role mapped", [
                'original' => $role,
                'mapped_to' => $roleMapping[$lowerRole]
            ]);
            return $roleMapping[$lowerRole];
        }

        // Pour tous les autres rôles, les préfixer avec ROLE_
        $normalized = 'ROLE_' . strtoupper($lowerRole);
        $this->logger?->debug("Role normalized", [
            'original' => $role,
            'normalized' => $normalized
        ]);
        return $normalized;
    }

    /**
     * Décode une chaîne base64 URL-safe (version améliorée)
     */
    private function base64UrlDecode(string $data): string|false
    {

        $data = trim($data);


        $data = strtr($data, '-_', '+/');


        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        // Décoder et vérifier le résultat
        $decoded = base64_decode($data, true); // strict mode

        if ($decoded === false) {
            $this->logger?->error('Base64 decoding failed', [
                'data_length' => strlen($data),
                'data_sample' => substr($data, 0, 50)
            ]);
            return false;
        }

        return $decoded;
    }
}
