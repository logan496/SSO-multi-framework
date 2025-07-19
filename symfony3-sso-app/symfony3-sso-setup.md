# Symfony 3 SSO Application Setup

## 1. Initialisation du projet Symfony 3

```bash
# Créer le projet Symfony 3
composer create-project symfony/framework-standard-edition symfony3-sso-app "3.4.*"
cd symfony3-sso-app

# Installer les dépendances nécessaires
composer require hwi/oauth-bundle "^0.6"
composer require doctrine/orm "^2.5"
composer require doctrine/doctrine-bundle "^1.6"
composer require sensio/framework-extra-bundle "^3.0"
composer require symfony/monolog-bundle "^3.0"
composer require symfony/swiftmailer-bundle "^2.3"
composer require guzzlehttp/guzzle "^6.0"
```

## 2. Configuration Keycloak - app/config/config.yml

```yaml
# HWI OAuth Bundle Configuration
hwi_oauth:
    firewall_names: [secured_area]
    resource_owners:
        keycloak:
            type: oauth2
            client_id: '%keycloak_client_id%'
            client_secret: '%keycloak_client_secret%'
            authorization_url: '%keycloak_server_url%/realms/%keycloak_realm%/protocol/openid-connect/auth'
            access_token_url: '%keycloak_server_url%/realms/%keycloak_realm%/protocol/openid-connect/token'
            infos_url: '%keycloak_server_url%/realms/%keycloak_realm%/protocol/openid-connect/userinfo'
            scope: "openid profile email"
            user_response_class: HWI\Bundle\OAuthBundle\OAuth\Response\PathUserResponse
            paths:
                identifier: sub
                nickname: preferred_username
                realname: name
                email: email
                profilepicture: picture

# Doctrine Configuration
doctrine:
    dbal:
        driver: pdo_sqlite
        path: '%kernel.root_dir%/../var/data/data.sqlite'
        charset: UTF8
    orm:
        auto_generate_proxy_classes: '%kernel.debug%'
        naming_strategy: doctrine.orm.naming_strategy.underscore
        auto_mapping: true
        mappings:
            AppBundle:
                mapping: true
                type: annotation
                dir: '%kernel.root_dir%/../src/AppBundle/Entity'
                alias: AppBundle
                prefix: AppBundle\Entity
                is_bundle: false
```

## 3. Configuration Security - app/config/security.yml

```yaml
security:
    encoders:
        AppBundle\Entity\User:
            algorithm: bcrypt
            cost: 12

    role_hierarchy:
        ROLE_ADMIN: ROLE_USER

    providers:
        our_db_provider:
            entity:
                class: AppBundle:User
                property: email
        hwi:
            id: hwi_oauth.user.provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        secured_area:
            pattern: ^/
            anonymous: true
            oauth:
                resource_owners:
                    keycloak: "/login/check-keycloak"
                login_path: /login
                use_forward: false
                failure_path: /login
                oauth_user_provider:
                    service: app.oauth_user_provider
            logout:
                path: /logout
                target: /login
                invalidate_session: true

    access_control:
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/oauth, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

## 4. Variables d'environnement - app/config/parameters.yml

```yaml
parameters:
    database_host: 127.0.0.1
    database_port: ~
    database_name: symfony
    database_user: root
    database_password: ~
    mailer_transport: smtp
    mailer_host: 127.0.0.1
    mailer_user: ~
    mailer_password: ~
    secret: ThisTokenIsNotSoSecretChangeIt
    
    # Keycloak Configuration
    keycloak_server_url: 'http://localhost:8080'
    keycloak_realm: 'multiframework-sso'
    keycloak_client_id: 'symfony3-app'
    keycloak_client_secret: 'your-client-secret'
```

## 5. Enregistrement du bundle - app/AppKernel.php

```php
<?php

use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Config\Loader\LoaderInterface;

class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = [
            new Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
            new Symfony\Bundle\SecurityBundle\SecurityBundle(),
            new Symfony\Bundle\TwigBundle\TwigBundle(),
            new Symfony\Bundle\MonologBundle\MonologBundle(),
            new Symfony\Bundle\SwiftmailerBundle\SwiftmailerBundle(),
            new Doctrine\Bundle\DoctrineBundle\DoctrineBundle(),
            new Sensio\Bundle\FrameworkExtraBundle\SensioFrameworkExtraBundle(),
            new HWI\Bundle\OAuthBundle\HWIOAuthBundle(),
            new AppBundle\AppBundle(),
        ];

        if (in_array($this->getEnvironment(), ['dev', 'test'], true)) {
            $bundles[] = new Symfony\Bundle\DebugBundle\DebugBundle();
            $bundles[] = new Symfony\Bundle\WebProfilerBundle\WebProfilerBundle();
            $bundles[] = new Sensio\Bundle\DistributionBundle\SensioDistributionBundle();
            $bundles[] = new Sensio\Bundle\GeneratorBundle\SensioGeneratorBundle();
        }

        return $bundles;
    }

    public function getRootDir()
    {
        return __DIR__;
    }

    public function getCacheDir()
    {
        return dirname(__DIR__).'/var/cache/'.$this->getEnvironment();
    }

    public function getLogDir()
    {
        return dirname(__DIR__).'/var/logs';
    }

    public function registerContainerConfiguration(LoaderInterface $loader)
    {
        $loader->load($this->getRootDir().'/config/config_'.$this->getEnvironment().'.yml');
    }
}
```

## 6. Entity User - src/AppBundle/Entity/User.php

```php
<?php

namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;

/**
 * @ORM\Entity(repositoryClass="AppBundle\Repository\UserRepository")
 * @ORM\Table(name="users")
 */
class User implements UserInterface
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(type="string", length=180, unique=true)
     */
    private $email;

    /**
     * @ORM\Column(type="json_array")
     */
    private $roles = [];

    /**
     * @ORM\Column(type="string", length=255)
     */
    private $name;

    /**
     * @ORM\Column(type="string", length=255, unique=true)
     */
    private $keycloakId;

    /**
     * @ORM\Column(type="datetime")
     */
    private $createdAt;

    /**
     * @ORM\Column(type="datetime")
     */
    private $updatedAt;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    private $username;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
        $this->updatedAt = new \DateTime();
        $this->roles = ['ROLE_USER'];
    }

    public function getId()
    {
        return $this->id;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function setEmail($email)
    {
        $this->email = $email;
        return $this;
    }

    public function getUsername()
    {
        return $this->username ?: $this->email;
    }

    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
    }

    public function getRoles()
    {
        $roles = $this->roles;
        if (!in_array('ROLE_USER', $roles)) {
            $roles[] = 'ROLE_USER';
        }
        return array_unique($roles);
    }

    public function setRoles(array $roles)
    {
        $this->roles = $roles;
        return $this;
    }

    public function getPassword()
    {
        return null;
    }

    public function getSalt()
    {
        return null;
    }

    public function eraseCredentials()
    {
        // Nothing to do here
    }

    public function getName()
    {
        return $this->name;
    }

    public function setName($name)
    {
        $this->name = $name;
        return $this;
    }

    public function getKeycloakId()
    {
        return $this->keycloakId;
    }

    public function setKeycloakId($keycloakId)
    {
        $this->keycloakId = $keycloakId;
        return $this;
    }

    public function getCreatedAt()
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTime $createdAt)
    {
        $this->createdAt = $createdAt;
        return $this;
    }

    public function getUpdatedAt()
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(\DateTime $updatedAt)
    {
        $this->updatedAt = $updatedAt;
        return $this;
    }

    public function updateFromOAuthResponse(UserResponseInterface $response)
    {
        $this->setKeycloakId($response->getUsername());
        $this->setEmail($response->getEmail());
        $this->setName($response->getRealName() ?: $response->getNickname());
        $this->setUsername($response->getNickname());
        $this->setUpdatedAt(new \DateTime());
    }
}
```

## 7. Repository User - src/AppBundle/Repository/UserRepository.php

```php
<?php

namespace AppBundle\Repository;

use AppBundle\Entity\User;
use Doctrine\ORM\EntityRepository;

class UserRepository extends EntityRepository
{
    public function findByKeycloakId($keycloakId)
    {
        return $this->findOneBy(['keycloakId' => $keycloakId]);
    }

    public function save(User $user)
    {
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }
}
```

## 8. OAuth User Provider - src/AppBundle/Security/OAuthUserProvider.php

```php
<?php

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
        $user = $userRepository->findByKeycloakId($keycloakId);

        if (!$user) {
            $user = new User();
            $user->setKeycloakId($keycloakId);
        }

        $user->updateFromOAuthResponse($response);
        $userRepository->save($user);

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

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === User::class;
    }
}
```

## 9. Services Configuration - app/config/services.yml

```yaml
services:
    app.oauth_user_provider:
        class: AppBundle\Security\OAuthUserProvider
        arguments: ['@doctrine.orm.entity_manager']
```

## 10. Routing - app/config/routing.yml

```yaml
hwi_oauth_redirect:
    resource: "@HWIOAuthBundle/Resources/config/routing/redirect.xml"
    prefix: /connect

hwi_oauth_connect:
    resource: "@HWIOAuthBundle/Resources/config/routing/connect.xml"
    prefix: /connect

hwi_oauth_login:
    resource: "@HWIOAuthBundle/Resources/config/routing/login.xml"
    prefix: /login

app:
    resource: '@AppBundle/Controller/'
    type: annotation
```

## 11. Controller Principal - src/AppBundle/Controller/DefaultController.php

```php
<?php

namespace AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="homepage")
     */
    public function indexAction(Request $request)
    {
        $user = $this->getUser();
        
        $apps = [
            'Laravel SSO App' => 'http://localhost:8000',
            'React SSO App' => 'http://localhost:3000',
            'Symfony 3 SSO App' => 'http://localhost:8002'
        ];

        return $this->render('default/dashboard.html.twig', [
            'user' => $user,
            'apps' => $apps,
        ]);
    }

    /**
     * @Route("/profile", name="profile")
     */
    public function profileAction()
    {
        return $this->render('default/profile.html.twig', [
            'user' => $this->getUser(),
        ]);
    }

    /**
     * @Route("/login", name="login")
     */
    public function loginAction()
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('homepage');
        }

        return $this->render('default/login.html.twig');
    }

    /**
     * @Route("/api/user", name="api_user", methods={"GET"})
     */
    public function getUserInfoAction()
    {
        $user = $this->getUser();
        
        return new JsonResponse([
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

    /**
     * @Route("/api/status", name="api_status", methods={"GET"})
     */
    public function getStatusAction()
    {
        return new JsonResponse([
            'success' => true,
            'data' => [
                'application' => 'Symfony 3 SSO App',
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

## 12. Template de base - app/Resources/views/base.html.twig

```twig
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>{% block title %}Symfony 3 SSO App{% endblock %}</title>
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

            .btn-keycloak {
                background: linear-gradient(45deg, #3498db, #2980b9);
                box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
            }

            .btn-keycloak:hover {
                box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
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

            .symfony-badge {
                background: linear-gradient(45deg, #000, #333);
                color: white;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 600;
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

## 13. Template Dashboard - app/Resources/views/default/dashboard.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Dashboard - Symfony 3 SSO App{% endblock %}

{% block body %}
    <div class="container">
        <div class="header">
            <div>
                <h1>Dashboard Symfony 3</h1>
                <span class="symfony-badge">Symfony 3.4 LTS</span>
            </div>
            <div class="user-info">
                <span>Bienvenue, {{ user.name }}</span>
                <a href="{{ path('profile') }}" class="btn btn-secondary">Profil</a>
                <a href="{{ path('hwi_oauth_service_redirect', {'service': 'keycloak'}) }}" class="btn">Se déconnecter</a>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Informations utilisateur</h2>
                <p><strong>Nom :</strong> {{ user.name }}</p>
                <p><strong>Email :</strong> {{ user.email }}</p>
                <p><strong>Keycloak ID :</strong> {{ user.keycloakId }}</p>
                <p><strong>Dernière connexion :</strong> {{ user.updatedAt|date('d/m/Y H:i') }}</p>
                
                <a href="{{ path('profile') }}" class="btn">Voir le profil</a>
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
                <p><strong>Application :</strong> Symfony 3 SSO App</p>
                <p><strong>Version :</strong> Symfony 3.4 LTS</p>
                <p><strong>Realm :</strong> multiframework-sso</p>
                <p><strong>Session :</strong> Active</p>
            </div>
        </div>
    </div>
{% endblock %}
```

## 14. Template Login - app/Resources/views/default/login.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Connexion - Symfony 3 SSO App{% endblock %}

{% block body %}
    <div class="login-container">
        <div class="login-card">
            <h1>Symfony 3 SSO App</h1>
            <span class="symfony-badge">Symfony 3.4 LTS</span>
            
            <p style="margin-top: 20px;">Connectez-vous avec votre compte Keycloak pour accéder à l'application Symfony 3.</p>
            
            <a href="{{ path('hwi_oauth_service_redirect', {'service': 'keycloak'}) }}" class="btn btn-keycloak">
                Se connecter avec Keycloak
            </a>
        </div>
    </div>
{% endblock %}
```

## 15. Template Profile - app/Resources/views/default/profile.html.twig

```twig
{% extends 'base.html.twig' %}

{% block title %}Profil - Symfony 3 SSO App{% endblock %}

{% block body %}
    <div class="container">
        <div class="header">
            <div>
                <h1>Mon Profil</h1>
                <span class="symfony-badge">Symfony 3.4 LTS</span>
            </div>
            <div class="user-info">
                <a href="{{ path('homepage') }}" class="btn btn-secondary">Retour au Dashboard</a>
                <a href="{{ path('hwi_oauth_service_redirect', {'service': 'keycloak'}) }}" class="btn">Se déconnecter</a>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Informations personnelles</h2>
                <p><strong>Nom complet :</strong> {{ user.name }}</p>
                <p><strong>Adresse email :</strong> {{ user.email }}</p>
                <p><strong>Nom d'utilisateur :</strong> {{ user.username }}</p>
                <p><strong>Identifiant Keycloak :</strong> {{ user.keycloakId }}</p>
                <p><strong>Rôles :</strong> {{ user.roles|join(', ') }}</p>
            </div>

            <div class="card">
                <h2>Informations de session</h2>
                <p><strong>Compte créé le :</strong> {{ user.createdAt|date('d/m/Y à H:i') }}</p>
                <p><strong>Dernière mise à jour :</strong> {{ user.updatedAt|date('d/m/Y à H:i') }}</p>
                <p><strong>Statut :</strong> <span class="status-connected">✓ Actif</span></p>
                <p><strong>Framework :</strong> Symfony 3.4 LTS</p>
            </div>
        </div>
    </div>
{% endblock %}
```

## 16. Configuration de la base de données

```bash
# Créer le schéma de base de données
php bin/console doctrine:database:create
php bin/console doctrine:schema:create

# Ou utiliser les migrations (si disponibles)
php bin/console doctrine:migrations:migrate
```

## 17. Configuration Keycloak Client

Dans votre console Keycloak, créez un nouveau client :

1. **Client ID:** `symfony3-app`
2. **Client Protocol:** `openid-connect`
3. **Access Type:** `confidential`
4. **Valid Redirect URIs:** `http://localhost:8002/login/check-keycloak`
5. **Web Origins:** `http://localhost:8002`

## 18. Lancement de l'application

```bash
# Démarrer le serveur Symfony 3
php bin/console server:run localhost:8002

# Ou avec PHP
php -S localhost:8002 -t web/
```

## URLs importantes

- **Application Symfony 3:** http://localhost:8002
- **Login:** http://localhost:8002/login
- **Dashboard:** http://localhost:8002/
- **Profile:** http://localhost:8002/profile
- **API User:** http://localhost:8002/api/user
- **API Status:** http://localhost:8002/api/status

## Points importants pour Symfony 3

1. **HWI OAuth Bundle** : Utilise la version 0.6 compatible avec Symfony 3
2. **Annotations** : Utilise les annotations pour le routing
3. **Doctrine** : Configuration pour Symfony 3 avec le mapping annotations