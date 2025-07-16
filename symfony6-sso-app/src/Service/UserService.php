<?php

namespace App\Service;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Response;

/**
 * @method findUserByKeycloakId(string $identifier)
 */
class UserService
{
    private EntityManagerInterface $entityManager;
    private string $keycloakUrl;
    private string $keycloakRealm;

    public function __construct(
        EntityManagerInterface $entityManager,
        string $keycloakUrl,
        string $keycloakRealm
    ) {
        $this->entityManager = $entityManager;
        $this->keycloakUrl = $keycloakUrl;
        $this->keycloakRealm = $keycloakRealm;
    }

    public function createOrUpdateUser(array $keycloakUserData): User
    {
        $user = $this->entityManager->getRepository(User::class)
            ->findOneBy(['keycloakId' => $keycloakUserData['sub']]);

        if (!$user) {
            $user = new User();
            $user->setKeycloakId($keycloakUserData['sub']);
        }

        $user->setUsername($keycloakUserData['preferred_username'] ?? $keycloakUserData['sub']);
        $user->setEmail($keycloakUserData['email'] ?? '');
        $user->setFirstName($keycloakUserData['given_name'] ?? null);
        $user->setLastName($keycloakUserData['family_name'] ?? null);

        // Gérer les rôles
        $roles = ['ROLE_USER'];
        if (isset($keycloakUserData['realm_access']['roles'])) {
            foreach ($keycloakUserData['realm_access']['roles'] as $role) {
                $roles[] = 'ROLE_' . strtoupper($role);
            }
        }
        $user->setRoles(array_unique($roles));

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    public function getUserInfo(string $accessToken): ?array
    {
        $client = HttpClient::create();
        $url = $this->keycloakUrl . '/realms/' . $this->keycloakRealm . '/protocol/openid-connect/userinfo';

        try {
            $response = $client->request('GET', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Accept' => 'application/json',
                ],
            ]);

            if ($response->getStatusCode() === Response::HTTP_OK) {
                return $response->toArray();
            }
        } catch (\Exception $e) {
            // Log l'erreur si nécessaire
        }

        return null;
    }

    public function logout(string $accessToken): bool
    {
        $client = HttpClient::create();
        $url = $this->keycloakUrl . '/realms/' . $this->keycloakRealm . '/protocol/openid-connect/logout';

        try {
            $response = $client->request('POST', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            return $response->getStatusCode() === Response::HTTP_NO_CONTENT;
        } catch (\Exception $e) {
            return false;
        }
    }
}