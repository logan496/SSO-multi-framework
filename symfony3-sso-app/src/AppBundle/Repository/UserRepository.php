<?php

namespace AppBundle\Repository;

use AppBundle\Entity\User;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\OptimisticLockException;

class UserRepository extends EntityRepository
{
    public function findByKeycloakId($keycloakId)
    {
        return $this->findOneBy(['keycloakId' => $keycloakId]);
    }

    /**
     * @throws OptimisticLockException
     */
    public function save(User $user)
    {
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }
}