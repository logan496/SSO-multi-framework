<?php
//
//namespace App\Controller;
//
//use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
//use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
//use Symfony\Component\HttpFoundation\Request;
//use Symfony\Component\HttpFoundation\Response;
//use Symfony\Component\Routing\Annotation\Route;
//
//class OAuthController extends AbstractController
//{
//    #[Route('/connect/keycloak', name: 'connect_keycloak_start')]
//    public function connectAction(ClientRegistry $clientRegistry): Response
//    {
//        return $clientRegistry
//            ->getClient('keycloak')
//            ->redirect([
//                'openid', 'profile', 'email', 'role'
//            ]);
//    }
//
//    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check')]
//    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry): Response
//    {
//        // Cette méthode sera gérée par le security authenticator
//        return new Response('Should not reach here');
//    }
//}


namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;

class OAuthController extends AbstractController
{
    public function __construct(private ?LoggerInterface $logger = null)
    {
    }

    #[Route('/connect/keycloak', name: 'connect_keycloak_start')]
    public function connectAction(ClientRegistry $clientRegistry): Response
    {
        $this->logger?->info('Starting Keycloak OAuth flow');

        return $clientRegistry
            ->getClient('keycloak')
            ->redirect([
                'openid', 'profile', 'email', 'roles'
            ], []);
    }

    #[Route('/connect/keycloak/check', name: 'connect_keycloak_check')]
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry): Response
    {
        $this->logger?->info('Keycloak callback received', [
            'query_params' => $request->query->all(),
            'has_code' => $request->query->has('code'),
            'has_error' => $request->query->has('error')
        ]);

        // Vérifier si on a une erreur de Keycloak
        if ($request->query->has('error')) {
            $error = $request->query->get('error');
            $errorDescription = $request->query->get('error_description', 'Unknown error');

            $this->logger?->error('Keycloak OAuth error', [
                'error' => $error,
                'description' => $errorDescription
            ]);

            throw new \Exception("Keycloak OAuth error: {$error} - {$errorDescription}");
        }

        // Vérifier si on a le code d'autorisation
        if (!$request->query->has('code')) {
            $this->logger?->error('Missing authorization code in callback');
            throw new \Exception('Authorization code missing from Keycloak callback');
        }

        // Cette méthode sera gérée par le security authenticator
        return new Response('Should not reach here');
    }
}
