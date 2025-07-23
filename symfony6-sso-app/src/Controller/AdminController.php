<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\RoleService;
use App\Service\KeycloakService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/admin')]
#[IsGranted("ROLE_ADMIN")]
class AdminController extends AbstractController
{
    private UserRepository $userRepository;
    private RoleService $roleService;
    private KeycloakService $keycloakService;

    public function __construct(
        UserRepository $userRepository,
        RoleService $roleService,
        KeycloakService $keycloakService
    ) {
        $this->userRepository = $userRepository;
        $this->roleService = $roleService;
        $this->keycloakService = $keycloakService;
    }

    #[Route('/', name: 'admin_dashboard')]
    public function dashboard(Request $request): Response
    {
        $users = $this->userRepository->findAll();
        $userStats = [
            'total' => count($users),
            'admins' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()))),
            'managers' => count(array_filter($users, fn($u) => in_array('ROLE_MANAGER', $u->getRoles()))),
            'users' => count(array_filter($users, fn($u) => !in_array('ROLE_ADMIN', $u->getRoles()) && !in_array('ROLE_MANAGER', $u->getRoles())))
        ];

        // Retourner JSON si demandé
        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'user' => $this->serializeUser($this->getUser()),
                    'users' => array_map([$this, 'serializeUser'], $users),
                    'stats' => $userStats,
                ]
            ]);
        }

        return $this->render('admin/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $users,
            'stats' => $userStats,
        ]);
    }

    #[Route('/users', name: 'admin_users')]
    public function users(Request $request): Response
    {
        $users = $this->userRepository->findAll();

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'users' => array_map([$this, 'serializeUser'], $users),
                    'roles' => $this->roleService->getAllRoles(),
                ]
            ]);
        }

        return $this->render('admin/users.html.twig', [
            'users' => $users,
            'roleService' => $this->roleService,
        ]);
    }

    #[Route('/system', name: 'admin_system')]
    public function system(Request $request): Response
    {
        $systemInfo = [
            'php_version' => PHP_VERSION,
            'symfony_version' => Kernel::VERSION,
            'server_time' => date('Y-m-d H:i:s'),
            'memory_usage' => round(memory_get_usage() / 1024 / 1024, 2) . 'MB',
            'memory_limit' => ini_get('memory_limit'),
            'keycloak_status' => $this->keycloakService->checkConnection(),
        ];

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'systemInfo' => $systemInfo,
                ]
            ]);
        }

        return $this->render('admin/system.html.twig', [
            'systemInfo' => $systemInfo,
        ]);
    }

    #[Route('/permissions', name: 'admin_permissions')]
    public function permissions(Request $request): Response
    {
        $allRoles = $this->roleService->getAllRoles();
        $permissions = [];

        foreach ($allRoles as $role) {
            $permissions[$role] = $this->roleService->getPermissionForRole($role);
        }

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'permissions' => $permissions,
                    'roles' => $allRoles,
                ]
            ]);
        }

        return $this->render('admin/permissions.html.twig', [
            'permissions' => $permissions,
            'roleService' => $this->roleService,
        ]);
    }

    // Routes API dédiées pour Laravel
    #[Route('/api/dashboard', name: 'admin_api_dashboard', methods: ['GET'])]
    public function apiDashboard(Request $request): JsonResponse
    {
        // Vérifier le token Keycloak
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $users = $this->userRepository->findAll();
        $userStats = [
            'total' => count($users),
            'admins' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()))),
            'managers' => count(array_filter($users, fn($u) => in_array('ROLE_MANAGER', $u->getRoles()))),
            'users' => count(array_filter($users, fn($u) => !in_array('ROLE_ADMIN', $u->getRoles()) && !in_array('ROLE_MANAGER', $u->getRoles())))
        ];

        return new JsonResponse([
            'success' => true,
            'data' => [
                'user' => $this->serializeUser($this->getUser()),
                'users' => array_map([$this, 'serializeUser'], $users),
                'stats' => $userStats,
            ]
        ]);
    }

    #[Route('/api/users', name: 'admin_api_users', methods: ['GET'])]
    public function apiUsers(Request $request): JsonResponse
    {
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $users = $this->userRepository->findAll();

        return new JsonResponse([
            'success' => true,
            'data' => [
                'users' => array_map([$this, 'serializeUser'], $users),
                'roles' => $this->roleService->getAllRoles(),
            ]
        ]);
    }


    #[Route('/api/permissions', name: 'admin_api_permissions', methods: ['GET'])]
    public function apiPermissions(Request $request): JsonResponse
    {
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $allRoles = $this->roleService->getAllRoles();
        $permissions = [];

        foreach ($allRoles as $role) {
            $permissions[$role] = $this->roleService->getPermissionForRole($role);
        }

        return new JsonResponse([
            'success' => true,
            'data' => [
                'permissions' => $permissions,
                'roles' => $allRoles,
            ]
        ]);
    }

    private function isJsonRequest(Request $request): bool
    {
        return $request->headers->get('Content-Type') === 'json' ||
            $request->headers->get('Accept') === 'application/json' ||
            str_contains($request->headers->get('Accept', ''), 'application/json');
    }

    private function validateKeycloakToken(Request $request): bool
    {
        $token = $request->headers->get('Authorization');

        if (!$token || !str_starts_with($token, 'Bearer ')) {
            return false;
        }

        $accessToken = substr($token, 7);
        return $this->keycloakService->validateToken($accessToken);
    }

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

