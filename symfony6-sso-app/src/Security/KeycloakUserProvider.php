<?php

namespace App\Security;

use App\Entity\User;
use App\Service\UserService;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakUserProvider implements UserProviderInterface
{
    private UserService $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        return $this->userService->findUserByKeycloakId($identifier);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException();
        }

        return $this->loadUserByIdentifier($user->getKeycloakId());
    }

    public function supportsClass(string $class): bool
    {
        return User::class === $class;
    }

    public function loadUserByUsername(string $username): UserInterface
    {
        return $this->loadUserByIdentifier($username);
    }
}

//
//namespace App\Security;
//
//use App\Entity\User;
//use App\Service\UserService;
//use Doctrine\ORM\EntityManagerInterface;
//use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
//use Symfony\Component\Security\Core\Exception\UserNotFoundException;
//use Symfony\Component\Security\Core\User\UserInterface;
//use Symfony\Component\Security\Core\User\UserProviderInterface;
//
//class KeycloakUserProvider implements UserProviderInterface
//{
//    private EntityManagerInterface $entityManager;
//    private UserService $userService;
//
//    public function __construct(EntityManagerInterface $entityManager, UserService $userService)
//    {
//        $this->entityManager = $entityManager;
//        $this->userService = $userService;
//    }
//
//    public function loadUserByIdentifier(string $identifier): UserInterface
//    {
//        $user = $this->entityManager->getRepository(User::class)
//            ->findOneBy(['keycloakId' => $identifier]);
//
//        if (!$user) {
//            throw new UserNotFoundException('User not found');
//        }
//
//        return $user;
//    }
//
//    public function refreshUser(UserInterface $user): UserInterface
//    {
//        if (!$user instanceof User) {
//            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
//        }
//
//        return $this->loadUserByIdentifier($user->getKeycloakId());
//    }
//
//    public function supportsClass(string $class): bool
//    {
//        return User::class === $class;
//    }
//}