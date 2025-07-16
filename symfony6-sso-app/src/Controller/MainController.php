<?php
//
//namespace App\Controller;
//
//use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
//use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
//use Symfony\Component\HttpFoundation\Response;
//use Symfony\Component\Routing\Annotation\Route;
//use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
//
//class MainController extends AbstractController
//{
//    #[Route('/', name: 'app_home')]
//    public function home(): Response
//    {
//        return $this->render('home.html.twig');
//    }
//
//    #[Route('/login', name: 'app_login')]
//    public function login(AuthenticationUtils $authenticationUtils): Response
//    {
//        if ($this->getUser()) {
//            return $this->redirectToRoute('app_dashboard');
//        }
//
//        $error = $authenticationUtils->getLastAuthenticationError();
//        $lastUsername = $authenticationUtils->getLastUsername();
//
//        return $this->render('login.html.twig', [
//            'last_username' => $lastUsername,
//            'error' => $error,
//        ]);
//    }
//
//    #[Route('/connect/keycloak', name: 'connect_keycloak_start')]
//    public function connectKeycloak(ClientRegistry $clientRegistry): Response
//    {
//        return $clientRegistry
//            ->getClient('keycloak')
//            ->redirect(['openid', 'profile', 'email']);
//    }
//
//    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check')]
//    public function connectKeycloakCheck(): Response
//    {
//        // Cette méthode sera gérée par l'authenticator
//        return $this->redirectToRoute('app_dashboard');
//    }
//
//    #[Route('/dashboard', name: 'app_dashboard')]
//    public function dashboard(): Response
//    {
//        $this->denyAccessUnlessGranted('ROLE_USER');
//
//        return $this->render('dashboard.html.twig', [
//            'user' => $this->getUser(),
//        ]);
//    }
//
//    #[Route('/profile', name: 'app_profile')]
//    public function profile(): Response
//    {
//        $this->denyAccessUnlessGranted('ROLE_USER');
//
//        return $this->render('profile.html.twig', [
//            'user' => $this->getUser(),
//        ]);
//    }
//
//    #[Route('/logout', name: 'app_logout')]
//    public function logout(): void
//    {
//        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
//    }
//}


namespace App\Controller;

use App\Service\UserService;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class MainController extends AbstractController
{
    private UserService $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    #[Route('/', name: 'app_home')]
    public function home(): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_dashboard');
        }

        return $this->render('home.html.twig');
    }

    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils, Request $request): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_dashboard');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        // Récupérer l'erreur depuis les paramètres de requête si présente
        $errorMessage = $request->query->get('error');

        return $this->render('login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
            'error_message' => $errorMessage,
        ]);
    }

    #[Route('/connect/keycloak', name: 'connect_keycloak_start')]
    public function connectKeycloak(ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry
            ->getClient('keycloak')
            ->redirect(['openid', 'profile', 'email']);
    }

    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check')]
    public function connectKeycloakCheck(): Response
    {
        // Cette méthode sera gérée par l'authenticator
        // En cas de problème, rediriger vers le dashboard
        return $this->redirectToRoute('app_dashboard');
    }

    #[Route('/dashboard', name: 'app_dashboard')]
    public function dashboard(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $user = $this->getUser();

        // Récupérer les données complètes depuis la session
        $keycloakData = $request->getSession()->get('keycloak_user_data', []);
        $userRoles = [];
        $userInfo = [];

        if (!empty($keycloakData)) {
            $userRoles = $this->userService->getUserRoles($keycloakData);
            $userInfo = [
                'first_name' => $keycloakData['given_name'] ?? null,
                'last_name' => $keycloakData['family_name'] ?? null,
                'email' => $keycloakData['email'] ?? $user->getEmail(),
                'username' => $keycloakData['preferred_username'] ?? $user->getUsername(),
                'keycloak_id' => $keycloakData['sub'] ?? null,
            ];
        }

        return $this->render('dashboard.html.twig', [
            'user' => $user,
            'user_info' => $userInfo,
            'user_roles' => $userRoles,
        ]);
    }

    #[Route('/profile', name: 'app_profile')]
    public function profile(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $user = $this->getUser();
        $accessToken = $request->getSession()->get('keycloak_access_token');

        // Récupérer les informations utilisateur depuis Keycloak
        $userInfo = null;
        if ($accessToken) {
            $userInfo = $this->userService->getUserInfo($accessToken);
        }

        // Fallback sur les données de session
        if (!$userInfo) {
            $keycloakData = $request->getSession()->get('keycloak_user_data', []);
            if (!empty($keycloakData)) {
                $userInfo = $keycloakData;
            }
        }

        return $this->render('profile.html.twig', [
            'user' => $user,
            'user_info' => $userInfo,
        ]);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(Request $request): Response
    {
        $accessToken = $request->getSession()->get('keycloak_access_token');

        if ($accessToken) {
            // Déconnecter de Keycloak
            $this->userService->logout($accessToken);
        }

        // La déconnexion locale sera gérée par Symfony Security
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}

