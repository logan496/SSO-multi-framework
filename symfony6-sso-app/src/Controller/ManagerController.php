<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\RoleService;
use App\Service\KeycloakService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/manager')]
#[IsGranted("ROLE_MANAGER")]
class ManagerController extends AbstractController
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

    #[Route('/', name: 'manager_dashboard')]
    public function dashboard(Request $request): Response
    {
        $users = $this->userRepository->findAll();

        $managedUsers = array_filter($users, function($user) {
            return !in_array('ROLE_ADMIN', $user->getRoles()) &&
                !in_array('ROLE_MANAGER', $user->getRoles());
        });

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'user' => $this->serializeUser($this->getUser()),
                    'users' => array_map([$this, 'serializeUser'], $managedUsers),
                    'totalUsers' => count($managedUsers),
                ]
            ]);
        }

        return $this->render('Manager/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $managedUsers,
            'totalUsers' => count($managedUsers),
        ]);
    }

    #[Route('/reports', name: 'manager_reports')]
    public function reports(Request $request): Response
    {
        $users = $this->userRepository->findAll();

        $stats = [
            'total_connections_today' => rand(10, 50),
            'active_users' => count($users),
            'new_users_this_week' => rand(1, 10)
        ];

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'stats' => $stats,
                ]
            ]);
        }

        return $this->render('Manager/reports.html.twig', [
            'stats' => $stats,
        ]);
    }

    #[Route('/team', name: 'manager_team')]
    public function team(Request $request): Response
    {
        $users = $this->userRepository->findAll();

        $teamMembers = array_filter($users, function($user) {
            return in_array('ROLE_USER', $user->getRoles()) &&
                !in_array('ROLE_ADMIN', $user->getRoles()) &&
                !in_array('ROLE_MANAGER', $user->getRoles());
        });

        if ($this->isJsonRequest($request)) {
            return new JsonResponse([
                'success' => true,
                'data' => [
                    'teamMembers' => array_map([$this, 'serializeUser'], $teamMembers),
                ]
            ]);
        }

        return $this->render('manager/team.html.twig', [
            'teamMembers' => $teamMembers,
        ]);
    }

    // Routes API dédiées
    #[Route('/api/dashboard', name: 'manager_api_dashboard', methods: ['GET'])]
    public function apiDashboard(Request $request): JsonResponse
    {
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $users = $this->userRepository->findAll();

        $managedUsers = array_filter($users, function($user) {
            return !in_array('ROLE_ADMIN', $user->getRoles()) &&
                !in_array('ROLE_MANAGER', $user->getRoles());
        });

        return new JsonResponse([
            'success' => true,
            'data' => [
                'user' => $this->serializeUser($this->getUser()),
                'users' => array_map([$this, 'serializeUser'], $managedUsers),
                'totalUsers' => count($managedUsers),
            ]
        ]);
    }

    #[Route('/api/reports', name: 'manager_api_reports', methods: ['GET'])]
    public function apiReports(Request $request): JsonResponse
    {
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $users = $this->userRepository->findAll();

        $stats = [
            'total_connections_today' => rand(10, 50),
            'active_users' => count($users),
            'new_users_this_week' => rand(1, 10)
        ];

        return new JsonResponse([
            'success' => true,
            'data' => [
                'stats' => $stats,
            ]
        ]);
    }

    #[Route('/api/team', name: 'manager_api_team', methods: ['GET'])]
    public function apiTeam(Request $request): JsonResponse
    {
        if (!$this->validateKeycloakToken($request)) {
            return new JsonResponse(['error' => 'Token invalide'], 401);
        }

        $users = $this->userRepository->findAll();

        $teamMembers = array_filter($users, function($user) {
            return in_array('ROLE_USER', $user->getRoles()) &&
                !in_array('ROLE_ADMIN', $user->getRoles()) &&
                !in_array('ROLE_MANAGER', $user->getRoles());
        });

        return new JsonResponse([
            'success' => true,
            'data' => [
                'teamMembers' => array_map([$this, 'serializeUser'], $teamMembers),
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
