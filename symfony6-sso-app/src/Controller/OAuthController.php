<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class OAuthController extends AbstractController
{
    #[Route('/connect/keycloak', name: 'connect_keycloak_start')]
    public function connectAction(ClientRegistry $clientRegistry): Response
    {
        return $clientRegistry
            ->getClient('keycloak')
            ->redirect([
                'openid', 'profile', 'email'
            ]);
    }

    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check')]
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry): Response
    {
        // Cette méthode sera gérée par le security authenticator
        return new Response('Should not reach here');
    }
}
