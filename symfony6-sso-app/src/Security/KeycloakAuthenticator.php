<?php
//
//namespace App\Security;
//
//use App\Entity\User;
//use Doctrine\ORM\EntityManagerInterface;
//use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
//use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
//use Symfony\Component\HttpFoundation\RedirectResponse;
//use Symfony\Component\HttpFoundation\Request;
//use Symfony\Component\HttpFoundation\Response;
//use Symfony\Component\Routing\RouterInterface;
//use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
//use Symfony\Component\Security\Core\Exception\AuthenticationException;
//use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
//use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
//use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
//
//class KeycloakAuthenticator extends OAuth2Authenticator
//{
//    private ClientRegistry $clientRegistry;
//    private EntityManagerInterface $entityManager;
//    private RouterInterface $router;
//
//    public function __construct(
//        ClientRegistry $clientRegistry,
//        EntityManagerInterface $entityManager,
//        RouterInterface $router
//    ) {
//        $this->clientRegistry = $clientRegistry;
//        $this->entityManager = $entityManager;
//        $this->router = $router;
//    }
//
//    public function supports(Request $request): ?bool
//    {
//        return $request->attributes->get('_route') === 'connect_keycloak_check';
//    }
//
//    public function authenticate(Request $request): Passport
//    {
//        $client = $this->clientRegistry->getClient('keycloak');
//        $accessToken = $this->fetchAccessToken($client);
//
//        return new SelfValidatingPassport(
//            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {
//                $keycloakUser = $client->fetchUserFromToken($accessToken);
//
//                $existingUser = $this->entityManager->getRepository(User::class)
//                    ->findOneBy(['keycloakId' => $keycloakUser->getId()]);
//
//                if ($existingUser) {
//                    return $existingUser;
//                }
//
//                // Créer un nouvel utilisateur
//                $user = new User();
//                $user->setKeycloakId($keycloakUser->getId());
//                $user->setUsername($keycloakUser->getUsername());
//                $user->setEmail($keycloakUser->getEmail());
//                $user->setFirstName($keycloakUser->getFirstName());
//                $user->setLastName($keycloakUser->getLastName());
//
//                $this->entityManager->persist($user);
//                $this->entityManager->flush();
//
//                return $user;
//            })
//        );
//    }
//
//    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
//    {
//        $targetUrl = $this->router->generate('app_dashboard');
//        return new RedirectResponse($targetUrl);
//    }
//
//    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
//    {
//        $message = strtr($exception->getMessageKey(), $exception->getMessageData());
//        return new Response($message, Response::HTTP_FORBIDDEN);
//    }
//}



namespace App\Security;

use App\Service\UserService;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use Stevenmaguire\OAuth2\Client\Provider\KeycloakResourceOwner;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class KeycloakAuthenticator extends OAuth2Authenticator
{
    private ClientRegistry $clientRegistry;
    private RouterInterface $router;
    private UserService $userService;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        UserService $userService
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->userService = $userService;
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'connect_keycloak_check';
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('keycloak');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {
                /** @var KeycloakResourceOwner $keycloakUser */
                $keycloakUser = $client->fetchUserFromToken($accessToken);

                $userData = $keycloakUser->toArray();

                // Créer ou mettre à jour l'utilisateur
                return $this->userService->createOrUpdateUser($userData);
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Rediriger vers la page d'accueil ou dashboard
        return new RedirectResponse($this->router->generate('app_dashboard'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new RedirectResponse($this->router->generate('app_login', ['error' => $message]));
    }
}