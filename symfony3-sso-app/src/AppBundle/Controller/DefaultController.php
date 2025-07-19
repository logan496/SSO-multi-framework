<?php

namespace AppBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class DefaultController extends Controller
{
    public function indexAction(Request $request)
    {
        $user = $this->getUser();

        $apps = [
            'Laravel SSO App' => 'http://localhost:8000',
            'React SSO App' => 'http://localhost:3000',
            'Symfony 3 SSO App' => 'http://localhost:8002'
        ];

        return $this->render('default/dashboard.html.twig', [
            'user' => $user,
            'apps' => $apps,
        ]);
    }

    public function profileAction()
    {
        return $this->render('default/profile.html.twig', [
            'user' => $this->getUser(),
        ]);
    }

    public function loginAction()
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('homepage');
        }

        return $this->render('default/login.html.twig');
    }

    public function getUserInfoAction()
    {
        $user = $this->getUser();

        if (!$user) {
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authenticated'
            ], 401);
        }

        return new JsonResponse([
            'success' => true,
            'data' => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail(),
                'keycloak_id' => $user->getKeycloakId(),
                'roles' => $user->getRoles(),
                'created_at' => $user->getCreatedAt()->format('Y-m-d H:i:s'),
                'updated_at' => $user->getUpdatedAt()->format('Y-m-d H:i:s'),
            ]
        ]);
    }

    public function getStatusAction()
    {
        return new JsonResponse([
            'success' => true,
            'data' => [
                'application' => 'Symfony 3 SSO App',
                'version' => '1.0.0',
                'status' => 'active',
                'realm' => 'multiframework-sso',
                'authenticated' => (bool)$this->getUser(),
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]);
    }
}