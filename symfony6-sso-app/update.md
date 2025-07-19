# 1. Configuration Security mise à jour - config/packages/security.yaml

```yaml
security:
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
            custom_authenticators:
                - App\Security\KeycloakAuthenticator
            entry_point: App\Security\KeycloakAuthenticator
            logout:
                path: app_logout
                target: app_login
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800
                path: /
                always_remember_me: true

    access_control:
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/connect, roles: PUBLIC_ACCESS }
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/manager, roles: ROLE_MANAGER }
        - { path: ^/api/admin, roles: ROLE_ADMIN }
        - { path: ^/, roles: IS_AUTHENTICATED_FULLY }

    role_hierarchy:
        ROLE_MANAGER: ROLE_USER
        ROLE_ADMIN: [ROLE_MANAGER, ROLE_USER]
        ROLE_SUPER_ADMIN: ROLE_ADMIN

# 2. Service pour la gestion des rôles - src/Service/RoleService.php

```php
<?php

namespace App\Service;

class RoleService
{
    private array $rolePermissions = [
        'ROLE_USER' => [
            'view_dashboard',
            'view_profile',
            'access_api_user'
        ],
        'ROLE_MANAGER' => [
            'view_dashboard',
            'view_profile',
            'access_api_user',
            'view_manager_panel',
            'manage_users',
            'view_reports'
        ],
        'ROLE_ADMIN' => [
            'view_dashboard',
            'view_profile',
            'access_api_user',
            'view_manager_panel',
            'manage_users',
            'view_reports',
            'view_admin_panel',
            'manage_system',
            'access_admin_api',
            'manage_permissions'
        ]
    ];

    public function hasPermission(array $userRoles, string $permission): bool
    {
        foreach ($userRoles as $role) {
            if (isset($this->rolePermissions[$role]) && 
                in_array($permission, $this->rolePermissions[$role])) {
                return true;
            }
        }
        return false;
    }

    public function getPermissionsForRole(string $role): array
    {
        return $this->rolePermissions[$role] ?? [];
    }

    public function getAllRoles(): array
    {
        return array_keys($this->rolePermissions);
    }

    public function getRoleLabel(string $role): string
    {
        $labels = [
            'ROLE_USER' => 'Utilisateur',
            'ROLE_MANAGER' => 'Manager',
            'ROLE_ADMIN' => 'Administrateur',
            'ROLE_SUPER_ADMIN' => 'Super Administrateur'
        ];

        return $labels[$role] ?? $role;
    }
}

# 3. Keycloak Authenticator mis à jour - src/Security/KeycloakAuthenticator.php

```php
<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
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

class KeycloakAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private ClientRegistry $clientRegistry;
    private RouterInterface $router;
    private UserRepository $userRepository;

    public function __construct(ClientRegistry $clientRegistry, RouterInterface $router, UserRepository $userRepository)
    {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->userRepository = $userRepository;
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'connect_keycloak_check';
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('keycloak');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {
                /** @var Keycloak $provider */
                $provider = $client->getOAuth2Provider();
                $keycloakUser = $provider->getResourceOwner($accessToken);

                $existingUser = $this->userRepository->findByKeycloakId($keycloakUser->getId());

                if ($existingUser) {
                    // Mettre à jour les rôles depuis Keycloak
                    $keycloakRoles = $this->extractRolesFromToken($accessToken);
                    $existingUser->setRoles($keycloakRoles);
                    $existingUser->setUpdatedAt(new \DateTimeImmutable());
                    $this->userRepository->save($existingUser, true);
                    return $existingUser;
                }

                $user = new User();
                $user->setKeycloakId($keycloakUser->getId());
                $user->setEmail($keycloakUser->getEmail());
                $user->setName($keycloakUser->getName() ?? $keycloakUser->getPreferredUsername());
                
                // Extraire les rôles depuis Keycloak
                $keycloakRoles = $this->extractRolesFromToken($accessToken);
                $user->setRoles($keycloakRoles);

                $this->userRepository->save($user, true);

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $user = $token->getUser();
        
        // Redirection basée sur le rôle
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return new RedirectResponse($this->router->generate('admin_dashboard'));
        } elseif (in_array('ROLE_MANAGER', $user->getRoles())) {
            return new RedirectResponse($this->router->generate('manager_dashboard'));
        }
        
        return new RedirectResponse($this->router->generate('app_dashboard'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    private function fetchAccessToken(OAuth2ClientInterface $client)
    {
        return $client->getAccessToken();
    }

    private function extractRolesFromToken($accessToken): array
    {
        // Décoder le token JWT pour extraire les rôles
        $tokenParts = explode('.', $accessToken->getToken());
        if (count($tokenParts) !== 3) {
            return ['ROLE_USER']; // Rôle par défaut
        }

        try {
            $payload = json_decode(base64_decode($tokenParts[1]), true);
            
            // Extraire les rôles depuis différentes sources possibles
            $roles = ['ROLE_USER']; // Rôle de base
            
            // Rôles depuis resource_access
            if (isset($payload['resource_access']['symfony-app']['roles'])) {
                foreach ($payload['resource_access']['symfony-app']['roles'] as $role) {
                    $roles[] = 'ROLE_' . strtoupper($role);
                }
            }
            
            // Rôles depuis realm_access
            if (isset($payload['realm_access']['roles'])) {
                foreach ($payload['realm_access']['roles'] as $role) {
                    if (in_array($role, ['admin', 'manager', 'user'])) {
                        $roles[] = 'ROLE_' . strtoupper($role);
                    }
                }
            }
            
            // Rôles depuis groups
            if (isset($payload['groups'])) {
                foreach ($payload['groups'] as $group) {
                    $groupName = str_replace('/', '', $group);
                    if (in_array($groupName, ['admin', 'manager', 'user'])) {
                        $roles[] = 'ROLE_' . strtoupper($groupName);
                    }
                }
            }
            
            return array_unique($roles);
        } catch (\Exception $e) {
            return ['ROLE_USER'];
        }
    }
}

# 4. Controller Admin - src/Controller/AdminController.php

```php
<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\RoleService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/admin')]
#[IsGranted('ROLE_ADMIN')]
class AdminController extends AbstractController
{
    private UserRepository $userRepository;
    private RoleService $roleService;

    public function __construct(UserRepository $userRepository, RoleService $roleService)
    {
        $this->userRepository = $userRepository;
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'admin_dashboard')]
    public function dashboard(): Response
    {
        $users = $this->userRepository->findAll();
        $userStats = [
            'total' => count($users),
            'admins' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()))),
            'managers' => count(array_filter($users, fn($u) => in_array('ROLE_MANAGER', $u->getRoles()))),
            'users' => count(array_filter($users, fn($u) => !in_array('ROLE_ADMIN', $u->getRoles()) && !in_array('ROLE_MANAGER', $u->getRoles())))
        ];

        return $this->render('admin/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $users,
            'stats' => $userStats,
        ]);
    }

    #[Route('/users', name: 'admin_users')]
    public function users(): Response
    {
        $users = $this->userRepository->findAll();
        
        return $this->render('admin/users.html.twig', [
            'users' => $users,
            'roleService' => $this->roleService,
        ]);
    }

    #[Route('/system', name: 'admin_system')]
    public function system(): Response
    {
        $systemInfo = [
            'php_version' => PHP_VERSION,
            'symfony_version' => \Symfony\Component\HttpKernel\Kernel::VERSION,
            'server_time' => date('Y-m-d H:i:s'),
            'memory_usage' => round(memory_get_usage() / 1024 / 1024, 2) . ' MB',
            'memory_limit' => ini_get('memory_limit'),
        ];

        return $this->render('admin/system.html.twig', [
            'systemInfo' => $systemInfo,
        ]);
    }

    #[Route('/permissions', name: 'admin_permissions')]
    public function permissions(): Response
    {
        $allRoles = $this->roleService->getAllRoles();
        $permissions = [];
        
        foreach ($allRoles as $role) {
            $permissions[$role] = $this->roleService->getPermissionsForRole($role);
        }

        return $this->render('admin/permissions.html.twig', [
            'permissions' => $permissions,
            'roleService' => $this->roleService,
        ]);
    }
}

# 5. Controller Manager - src/Controller/ManagerController.php

```php
<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\RoleService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/manager')]
#[IsGranted('ROLE_MANAGER')]
class ManagerController extends AbstractController
{
    private UserRepository $userRepository;
    private RoleService $roleService;

    public function __construct(UserRepository $userRepository, RoleService $roleService)
    {
        $this->userRepository = $userRepository;
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'manager_dashboard')]
    public function dashboard(): Response
    {
        $users = $this->userRepository->findAll();
        
        // Les managers ne voient que les utilisateurs normaux
        $managedUsers = array_filter($users, function($user) {
            return !in_array('ROLE_ADMIN', $user->getRoles()) && 
                   !in_array('ROLE_MANAGER', $user->getRoles());
        });

        return $this->render('manager/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $managedUsers,
            'totalUsers' => count($managedUsers),
        ]);
    }

    #[Route('/reports', name: 'manager_reports')]
    public function reports(): Response
    {
        $users = $this->userRepository->findAll();
        
        // Statistiques pour les managers
        $stats = [
            'total_connections_today' => rand(10, 50), // Simulation
            'active_users' => count($users),
            'new_users_this_week' => rand(1, 10),
        ];

        return $this->render('manager/reports.html.twig', [
            'stats' => $stats,
        ]);
    }

    #[Route('/team', name: 'manager_team')]
    public function team(): Response
    {
        $users = $this->userRepository->findAll();
        
        $teamMembers = array_filter($users, function($user) {
            return in_array('ROLE_USER', $user->getRoles()) && 
                   !in_array('ROLE_ADMIN', $user->getRoles()) && 
                   !in_array('ROLE_MANAGER', $user->getRoles());
        });

        return $this->render('manager/team.html.twig', [
            'teamMembers' => $teamMembers,
        ]);
    }
}

# 6. Controller Principal mis à jour - src/Controller/MainController.php

```php
<?php

namespace App\Controller;

use App\Service\RoleService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class MainController extends AbstractController
{
    private RoleService $roleService;

    public function __construct(RoleService $roleService)
    {
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'app_dashboard')]
    public function dashboard(): Response
    {
        $user = $this->getUser();
        
        // Redirection automatique vers le bon dashboard selon le rôle
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return $this->redirectToRoute('admin_dashboard');
        } elseif (in_array('ROLE_MANAGER', $user->getRoles())) {
            return $this->redirectToRoute('manager_dashboard');
        }
        
        $apps = [
            'Laravel SSO App' => 'http://localhost:8000',
            'React SSO App' => 'http://localhost:3000',
            'Symfony SSO App' => 'http://localhost:8001'
        ];

        // Menus selon les permissions
        $availableMenus = [];
        if ($this->roleService->hasPermission($user->getRoles(), 'view_manager_panel')) {
            $availableMenus['Manager'] = $this->generateUrl('manager_dashboard');
        }
        if ($this->roleService->hasPermission($user->getRoles(), 'view_admin_panel')) {
            $availableMenus['Administration'] = $this->generateUrl('admin_dashboard');
        }

        return $this->render('dashboard.html.twig', [
            'user' => $user,
            'apps' => $apps,
            'menus' => $availableMenus,
            'roleService' => $this->roleService,
        ]);
    }

    #[Route('/profile', name: 'app_profile')]
    public function profile(): Response
    {
        return $this->render('profile.html.twig', [
            'user' => $this->getUser(),
            'roleService' => $this->roleService,
        ]);
    }

    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_dashboard');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route('/access-denied', name: 'access_denied')]
    public function accessDenied(): Response
    {
        return $this->render('access_denied.html.twig');
    }
}
