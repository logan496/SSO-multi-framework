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
#[IsGranted("ROLE_ADMIN")]
class AdminController extends AbstractController
{
    private UserRepository $userRepository;
    private RoleService $roleService;

    public function __construct(UserRepository $userRepository, RoleService $roleService){
        $this->userRepository = $userRepository;
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'admin_dashboard')]
    public function dashboard(): Response {
        $users = $this->userRepository->findAll();
        $userStats = [
            'total' => count($users),
            'admins' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()))),
            'managers' => count(array_filter($users, fn($u) => in_array('ROLE_MANAGER', $u->getRoles()))),
            'users' => count(array_filter($users, fn($u) => in_array('ROLE_ADMIN', $u->getRoles()) && !in_array('ROLE_MANAGER', $u->getRoles())))
        ];

        return $this->render('admin/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $users,
            'stats' => $userStats,
        ]);
    }

    #[Route('/users', name: 'admin_users')]
    public function users(): Response {
        $users = $this->userRepository->findAll();

        return $this->render('admin/users.html.twig', [
            'users' => $users,
            'roleService' => $this->roleService,
        ]);
    }

    #[Route('/system', name: 'admin_system')]
    public function system(): Response {
        $systemInfo = [
            'php_version' => PHP_VERSION,
            'symfony_version' => \Symfony\Component\HttpKernel\Kernel::VERSION,
            'server_time' => date('Y-m-d H:i:s'),
            'memory_usage' => round(memory_get_usage() / 1024 / 1024, 2) . 'MB',
            'memory_limit' => ini_get('memory_limit'),
        ];

        return $this->render('admin/system.html.twig', [
            'systemInfo' => $systemInfo,
        ]);
    }

    #[Route('/permissions', name: 'admin_permissions')]
    public function permissions(): Response {
        $allRoles = $this->roleService->getAllRoles();
        $permissions = [];

        foreach ($allRoles as $role) {
            $permissions[$role] = $this->roleService->getPermissionForRole($role);
        }

        return $this->render('admin/permissions.html.twig', [
            'permissions' => $permissions,
            'roleService' => $this->roleService,
        ]);

    }

}
