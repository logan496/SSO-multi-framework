# Symfony 6 SSO Application Setup

## 1. Initialisation du projet Symfony

```bash
# Créer le projet Symfony 6
composer create-project symfony/skeleton symfony-sso-app
cd symfony-sso-app

# Installer les dépendances nécessaires
composer require symfony/webapp-pack
composer require symfony/security-bundle
composer require knpuniversity/oauth2-client-bundle
composer require stevenmaguire/oauth2-keycloak
composer require symfony/twig-bundle
composer require symfony/asset
composer require symfony/webpack-encore-bundle
composer require doctrine/doctrine-bundle
composer require doctrine/orm
composer require symfony/maker-bundle --dev
```

## 2. Configuration Keycloak - config/packages/knpu_oauth2_client.yaml

```yaml
knpu_oauth2_client:
    clients:
        keycloak:
            type: keycloak
            client_id: '%env(KEYCLOAK_CLIENT_ID)%'
            client_secret: '%env(KEYCLOAK_CLIENT_SECRET)%'
            redirect_route: connect_keycloak_check
            redirect_params: {}
            auth_server_url: '%env(KEYCLOAK_SERVER_URL)%'
            realm: '%env(KEYCLOAK_REALM)%'
            encryption_algorithm: 'RS256'
            encryption_key_path: null
            encryption_key: null
            use_state: true
```

## 3. Configuration Security - config/packages/security.yaml

```yaml
security:
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
            custom_authenticators:
                - App\Security\KeycloakAuthenticator
            entry_point: App\Security\KeycloakAuthenticator
            logout:
                path: app_logout
                target: app_login
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800
                path: /
                always_remember_me: true

    access_control:
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/connect, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: IS_AUTHENTICATED_FULLY }

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER
```

## 4. Variables d'environnement - .env

```env
# Keycloak Configuration
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=multiframework-sso
KEYCLOAK_CLIENT_ID=symfony-app
KEYCLOAK_CLIENT_SECRET=your-client-secret

# Database (optionnel pour ce projet)
DATABASE_URL="sqlite:///%kernel.project_dir%/var/data.db"
```

## 5. Entity User - src/Entity/User.php

```php
<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180, unique: true)]
    private ?string $email = null;

    #[ORM\Column]
    private array $roles = [];

    #[ORM\Column(nullable: true)]
    private ?string $password = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column(length: 255, unique: true)]
    private ?string $keycloakId = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $updatedAt = null;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
        $this->updatedAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;
        return $this;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';
        return array_unique($roles);
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;
        return $this;
    }

    public function getPassword(): string
    {
        return $this->password ?? '';
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;
        return $this;
    }

    public function eraseCredentials(): void
    {
        // Effacer les données sensibles temporaires
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    public function getKeycloakId(): ?string
    {
        return $this->keycloakId;
    }

    public function setKeycloakId(string $keycloakId): static
    {
        $this->keycloakId = $keycloakId;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;
        return $this;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(\DateTimeImmutable $updatedAt): static
    {
        $this->updatedAt = $updatedAt;
        return $this;
    }
}
```

## 6. Repository User - src/Repository/UserRepository.php

```php
<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findByKeycloakId(string $keycloakId): ?User
    {
        return $this->findOneBy(['keycloakId' => $keycloakId]);
    }

    public function save(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
```

## 7. Keycloak Authenticator - src/Security/KeycloakAuthenticator.php

```php
<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class KeycloakAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    private ClientRegistry $clientRegistry;
    private RouterInterface $router;
    private UserRepository $userRepository;

    public function __construct(ClientRegistry $clientRegistry, RouterInterface $router, UserRepository $userRepository)
    {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->userRepository = $userRepository;
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
                /** @var Keycloak $provider */
                $provider = $client->getOAuth2Provider();
                $keycloakUser = $provider->getResourceOwner($accessToken);

                $existingUser = $this->userRepository->findByKeycloakId($keycloakUser->getId());

                if ($existingUser) {
                    $existingUser->setUpdatedAt(new \DateTimeImmutable());
                    $this->userRepository->save($existingUser, true);
                    return $existingUser;
                }

                $user = new User();
                $user->setKeycloakId($keycloakUser->getId());
                $user->setEmail($keycloakUser->getEmail());
                $user->setName($keycloakUser->getName() ?? $keycloakUser->getPreferredUsername());
                $user->setRoles(['ROLE_USER']);

                $this->userRepository->save($user, true);

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse($this->router->generate('app_dashboard'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate('app_login'));
    }

    private function fetchAccessToken(OAuth2ClientInterface $client)
    {
        return $client->getAccessToken();
    }
}
```

## 8. Controller Principal - src/Controller/MainController.php

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class MainController extends AbstractController
{
    #[Route('/', name: 'app_dashboard')]
    public function dashboard(): Response
    {
        $user = $this->getUser();
        
        $apps = [
            'Laravel SSO App' => 'http://localhost:8000',
            'React SSO App' => 'http://localhost:3000',
            'Symfony SSO App' => 'http://localhost:8001'
        ];

        return $this->render('dashboard.html.twig', [
            'user' => $user,
            'apps' => $apps,
        ]);
    }

    #[Route('/profile', name: 'app_profile')]
    public function profile(): Response
    {
        return $this->render('profile.html.twig', [
            'user' => $this->getUser(),
        ]);
    }

    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_dashboard');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
```

## 9. OAuth Controller - src/Controller/OAuthController.php

```php
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
```

## 10. API Controller - src/Controller/ApiController.php

```php
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
                'authenticated' => $this->getUser() ? true : false,
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]);
    }
}
```

## 11. Template de base - templates/base.html.twig

```twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>{% block title %}Symfony SSO App{% endblock %}</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 128 128%22><text y=%221.2em%22 font-size=%2296%22>⚫️</text></svg>">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .header {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 15px;
                padding: 20px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                color: white;
            }

            .header h1 {
                font-size: 2rem;
                font-weight: 700;
            }

            .header .user-info {
                display: flex;
                align-items: center;
                gap: 15px;
            }

            .btn {
                display: inline-block;
                padding: 12px 24px;
                background: linear-gradient(45deg, #ff6b6b, #ff8e8e);
                color: white;
                text-decoration: none;
                border-radius: 25px;
                font-weight: 600;
                transition: all 0.3s ease;
                border: none;
                cursor: pointer;
                box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);
            }

            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(255, 107, 107, 0.4);
            }

            .btn-secondary {
                background: linear-gradient(45deg, #4ecdc4, #44a08d);
                box-shadow: 0 4px 15px rgba(78, 205, 196, 0.3);
            }

            .btn-secondary:hover {
                box-shadow: 0 6px 20px rgba(78, 205, 196, 0.4);
            }

            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin-top: 30px;
            }

            .card {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 20px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                backdrop-filter: blur(10px);
                transition: transform 0.3s ease;
            }

            .card:hover {
                transform: translateY(-5px);
            }

            .card h2 {
                color: #333;
                margin-bottom: 20px;
                font-size: 1.5rem;
                font-weight: 600;
            }

            .card p {
                margin-bottom: 15px;
                line-height: 1.6;
                color: #666;
            }

            .card p strong {
                color: #333;
            }

            .status-connected {
                color: #27ae60;
                font-weight: 600;
            }

            .login-container {
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }

            .login-card {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                backdrop-filter: blur(10px);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }

            .login-card h1 {
                margin-bottom: 30px;
                color: #333;
            }

            .login-card p {
                margin-bottom: 30px;
                color: #666;
                line-height: 1.6;
            }

            .error {
                background: #fee;
                color: #c33;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 20px;
            }

            @media (max-width: 768px) {
                .header {
                    flex-direction: column;
                    gap: 15px;
                    text-align: center;
                }

                .grid {
                    grid-template-columns: 1fr;
                }

                .container {
                    padding: 15px;
                }
            }
        </style>
    </head>
    <body>
        {% block body %}{% endblock %}
    </body>
</html>
```

## 12. Template Dashboard - templates/dashboard.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Dashboard - Symfony SSO App{% endblock %}

{% block body %}
    <div class="container">
        <div class="header">
            <h1>Dashboard Symfony</h1>
            <div class="user-info">
                <span>Bienvenue, {{ user.name }}</span>
                <a href="{{ path('app_logout') }}" class="btn">Se déconnecter</a>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Informations utilisateur</h2>
                <p><strong>Nom :</strong> {{ user.name }}</p>
                <p><strong>Email :</strong> {{ user.email }}</p>
                <p><strong>Keycloak ID :</strong> {{ user.keycloakId }}</p>
                <p><strong>Dernière connexion :</strong> {{ user.updatedAt.format('d/m/Y H:i') }}</p>
                
                <a href="{{ path('app_profile') }}" class="btn">Voir le profil</a>
            </div>

            <div class="card">
                <h2>Applications du Challenge</h2>
                <p>Accédez aux autres applications sans vous reconnecter :</p>
                
                {% for name, url in apps %}
                    <div style="margin-bottom: 0.5rem;">
                        <a href="{{ url }}" class="btn" target="_blank">{{ name }}</a>
                    </div>
                {% endfor %}
            </div>

            <div class="card">
                <h2>API Endpoints</h2>
                <p>Testez les endpoints API :</p>
                
                <div style="margin-bottom: 0.5rem;">
                    <a href="{{ path('api_user') }}" class="btn" target="_blank">GET /api/user</a>
                </div>
                <div style="margin-bottom: 0.5rem;">
                    <a href="{{ path('api_status') }}" class="btn" target="_blank">GET /api/status</a>
                </div>
            </div>

            <div class="card">
                <h2>Statut SSO</h2>
                <p><strong>Statut :</strong> <span class="status-connected">✓ Connecté</span></p>
                <p><strong>Application :</strong> Symfony SSO App</p>
                <p><strong>Realm :</strong> multiframework-sso</p>
                <p><strong>Session :</strong> Active</p>
            </div>
        </div>
    </div>
{% endblock %}
```

## 13. Template Login - templates/login.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Connexion - Symfony SSO App{% endblock %}

{% block body %}
    <div class="login-container">
        <div class="login-card">
            <h1>Symfony SSO App</h1>
            
            {% if error %}
                <div class="error">{{ error.messageKey|trans(error.messageData, 'security') }}</div>
            {% endif %}
            
            <p>Connectez-vous avec votre compte Keycloak pour accéder à l'application.</p>
            
            <a href="{{ path('connect_keycloak_start') }}" class="btn">
                Se connecter avec Keycloak
            </a>
        </div>
    </div>
{% endblock %}
```

## 14. Template Profile - templates/profile.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Profil - Symfony SSO App{% endblock %}

{% block body %}
    <div class="container">
        <div class="header">
            <h1>Mon Profil</h1>
            <div class="user-info">
                <a href="{{ path('app_dashboard') }}" class="btn btn-secondary">Retour au Dashboard</a>
                <a href="{{ path('app_logout') }}" class="btn">Se déconnecter</a>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Informations personnelles</h2>
                <p><strong>Nom complet :</strong> {{ user.name }}</p>
                <p><strong>Adresse email :</strong> {{ user.email }}</p>
                <p><strong>Identifiant Keycloak :</strong> {{ user.keycloakId }}</p>
                <p><strong>Rôles :</strong> {{ user.roles|join(', ') }}</p>
            </div>

            <div class="card">
                <h2>Informations de session</h2>
                <p><strong>Compte créé le :</strong> {{ user.createdAt.format('d/m/Y à H:i') }}</p>
                <p><strong>Dernière mise à jour :</strong> {{ user.updatedAt.format('d/m/Y à H:i') }}</p>
                <p><strong>Statut :</strong> <span class="status-connected">✓ Actif</span></p>
            </div>
        </div>
    </div>
{% endblock %}
```

## 15. Migration Database

```bash
# Créer la migration.php
php bin/console make:migration.php

# Exécuter la migration.php
php bin/console doctrine:migrations:migrate
```

## 16. Configuration Keycloak Client

Dans votre console Keycloak, créez un nouveau client :

1. **Client ID:** `symfony-app`
2. **Client Protocol:** `openid-connect`
3. **Access Type:** `confidential`
4. **Valid Redirect URIs:** `http://localhost:8001/connect/keycloak/check`
5. **Web Origins:** `http://localhost:8001`

## 17. Lancement de l'application

```bash
# Démarrer le serveur Symfony
symfony server:start --port=8001

# Ou avec PHP
php -S localhost:8001 -t public/
```

## URLs importantes

- **Application Symfony:** http://localhost:8001
- **Login:** http://localhost:8001/login
- **Dashboard:** http://localhost:8001/
- **Profile:** http://localhost:8001/profile
- **API User:** http://localhost:8001/api/user
- **API Status:** http://localhost:8001/api/status

L'application est maintenant prête et intégrée avec Keycloak SSO. Les utilisateurs connectés sur Laravel pourront accéder à Symfony sans se reconnecter.
