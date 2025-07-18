<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api')]
class ApiController extends AbstractController
{
    #[Route('/user', name: 'api_user', methods: ['GET'])]
    public function getUserInfo(): JsonResponse
    {
        $user = $this->getUser();

        return $this->json([
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

    #[Route('/status', name: 'api_status', methods: ['GET'])]
    public function getStatus(): JsonResponse
    {
        return $this->json([
            'success' => true,
            'data' => [
                'application' => 'Symfony SSO App',
                'version' => '1.0.0',
                'status' => 'active',
                'realm' => 'multiframework-sso',
                'authenticated' => (bool)$this->getUser(),
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]);
    }
}
