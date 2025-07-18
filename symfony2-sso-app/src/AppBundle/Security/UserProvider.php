<?php

namespace AppBundle\Security;

use AppBundle\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface, OAuthAwareUserProviderInterface
{
    private $em;

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        $keycloakId = $response->getUsername();

        $user = $this->em->getRepository(User::class)->findOneBy(['keycloakId' => $keycloakId]);

        if (!$user) {
            $user = new User();
            $user->setKeycloakId($keycloakId);
        }

        $user->setUsername($response->getNickname() ?: $response->getEmail());
        $user->setEmail($response->getEmail());

        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }

    public function loadUserByUsername($username)
    {
        return $this->em->getRepository(User::class)->findOneBy(['username' => $username]);
    }

    public function refreshUser(UserInterface $user)
    {
        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return User::class === $class || is_subclass_of($class, User::class);
    }
}