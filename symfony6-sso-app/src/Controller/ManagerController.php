<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\RoleService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/manager')]
#[IsGranted("ROLE_MANAGER")]
class ManagerController extends AbstractController
{
    private UserRepository $userRepository;
    private RoleService $roleService;

    public function __construct(UserRepository $userRepository, RoleService $roleService){
        $this->userRepository = $userRepository;
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'manager_dashboard')]
    public function dashboard(): Response {
        $users = $this->userRepository->findAll();

        // Les managers ne voient que les utilisateurs normaux
        $managedUsers = array_filter($users, function($user) {
            return !in_array('ROLE_ADMIN', $user->getRoles()) &&
                !in_array('ROLE_MANAGER', $user->getRoles());
        });

        return $this->render('Manager/dashboard.html.twig', [
            'user' => $this->getUser(),
            'users' => $managedUsers,
            'totalUsers' => count($managedUsers),
        ]);
    }

    #[Route('/reports', name: 'manager_reports')]
    public function reports(): Response {
        $users = $this->userRepository->findAll();

        $stats = [
            'total_connections_today' => rand(10, 50), // simulation des nombres de connexions
            'active_users' => count($users),
            'new_users_this_week' => rand(1, 10)
        ];

        return $this->render ('Manager/reports.html.twig', [
            'stats' => $users,
        ]);
    }

    public function team(): Response {
        $users = $this->userRepository->findAll();

        $teamMembers = array_filter($users, function($user) {
            return  !in_array('ROLE_USER', $user->getRoles()) &&
                    !in_array('ROLE_ADMIN', $user->getRoles()) &&
                    !in_array('ROLE_MANAGER', $user->getRoles());

        });

        return $this->render('manager/team.html.twig', [
            'teamMembers' => $teamMembers,
        ]);
    }
}
