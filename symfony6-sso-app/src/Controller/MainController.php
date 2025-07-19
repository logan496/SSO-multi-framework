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
    public function __construct(RoleService $roleService) {
        $this->roleService = $roleService;
    }

    #[Route('/', name: 'app_dashboard')]
    public function dashboard(): Response
    {
        $user = $this->getUser();

        // redirection to dashboard according to the role
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

        // Menu according to permissions
        $availableMenus = [];
        if ($this->roleService->hasPermission($user->getRoles(), 'view_manager_panel')){
            $availableMenus['Manager'] = $this->generateUrl('manager_dashboard');
        }
        if ($this->roleService->hasPermission($user->getRoles(), 'view_admin_panel')){
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

    public function accessDenied(): Response {
        return $this->render('access_denied.html.twig');
    }
}
