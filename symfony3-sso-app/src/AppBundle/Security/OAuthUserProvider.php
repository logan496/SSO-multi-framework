<?php
//
//namespace AppBundle\Security;
//
//use AppBundle\Entity\User;
//use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
//use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthUserProvider as BaseOAuthUserProvider;
//use Symfony\Component\Security\Core\User\UserInterface;
//use Symfony\Component\Security\Core\User\UserProviderInterface;
//use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
//use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
//use Doctrine\ORM\EntityManagerInterface;
//
//class OAuthUserProvider extends BaseOAuthUserProvider implements UserProviderInterface
//{
//    private $entityManager;
//
//    public function __construct(EntityManagerInterface $entityManager)
//    {
//        $this->entityManager = $entityManager;
//    }
//
//    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
//    {
//        $keycloakId = $response->getUsername(); // 'sub' field from Keycloak
//
//        $userRepository = $this->entityManager->getRepository(User::class);
//        $user = $userRepository->findByKeycloakId($keycloakId);
//
//        if (!$user) {
//            $user = new User();
//            $user->setKeycloakId($keycloakId);
//        }
//
//        $user->updateFromOAuthResponse($response);
//        $userRepository->save($user);
//
//        return $user;
//    }
//
//    public function loadUserByUsername($username)
//    {
//        $userRepository = $this->entityManager->getRepository(User::class);
//        $user = $userRepository->findOneBy(['email' => $username]);
//
//        if (!$user) {
//            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
//        }
//
//        return $user;
//    }
//
//    public function refreshUser(UserInterface $user)
//    {
//        if (!$this->supportsClass(get_class($user))) {
//            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
//        }
//
//        return $this->loadUserByUsername($user->getUsername());
//    }
//
//    public function supportsClass($class)
//    {
//        return $class === User::class;
//    }
//}


namespace AppBundle\Security;

use AppBundle\Entity\User;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthUserProvider as BaseOAuthUserProvider;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Doctrine\ORM\EntityManagerInterface;

class OAuthUserProvider extends BaseOAuthUserProvider implements UserProviderInterface
{
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        $keycloakId = $response->getUsername(); // 'sub' field from Keycloak

        $userRepository = $this->entityManager->getRepository(User::class);
        $user = $userRepository->findOneBy(['keycloakId' => $keycloakId]);

        if (!$user) {
            $user = new User();
            $user->setKeycloakId($keycloakId);
        }

        // Mettre à jour les informations utilisateur
        $user->setName($response->getRealName());
        $user->setEmail($response->getEmail());

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    public function loadUserByUsername($username)
    {
        $userRepository = $this->entityManager->getRepository(User::class);
        $user = $userRepository->findOneBy(['email' => $username]);

        if (!$user) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        return $user;
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getEmail());
    }

    public function supportsClass($class)
    {
        return $class === User::class || is_subclass_of($class, User::class);
    }
}