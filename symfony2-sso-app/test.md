# Application Symfony 2 avec SSO Keycloak

## 1. Installation et Configuration de Base

### Prérequis
- PHP 5.6 ou supérieur
- Composer
- Serveur web (Apache/Nginx)
- Keycloak server

### Installation de Symfony 2
```bash
# Créer le projet Symfony 2
composer create-project symfony/framework-standard-edition symfony2-sso-app "2.8.*"
cd symfony2-sso-app

# Installer les dépendances OAuth2
composer require "hwi/oauth-bundle:^0.6"
composer require "guzzlehttp/guzzle:^6.0"
```

## 2. Configuration Keycloak

### Configuration dans `app/config/config.yml`
```yaml
# app/config/config.yml
imports:
    - { resource: parameters.yml }
    - { resource: security.yml }
    - { resource: services.yml }

framework:
    secret: "%secret%"
    router:
        resource: "%kernel.root_dir%/config/routing.yml"
        strict_requirements: ~
    form: ~
    csrf_protection: ~
    validation: { enable_annotations: true }
    templating:
        engines: ['twig']
    session:
        handler_id: ~
        cookie_lifetime: 3600
    translator: { fallbacks: ["%locale%"] }

# Twig Configuration
twig:
    debug: "%kernel.debug%"
    strict_variables: "%kernel.debug%"

# HWI OAuth Configuration
hwi_oauth:
    firewall_names: [main]
    fosub:
        username_iterations: 30
        properties:
            keycloak: keycloak_id
    resource_owners:
        keycloak:
            type: oauth2
            client_id: "%keycloak_client_id%"
            client_secret: "%keycloak_client_secret%"
            authorization_url: "%keycloak_server_url%/auth/realms/%keycloak_realm%/protocol/openid-connect/auth"
            access_token_url: "%keycloak_server_url%/auth/realms/%keycloak_realm%/protocol/openid-connect/token"
            infos_url: "%keycloak_server_url%/auth/realms/%keycloak_realm%/protocol/openid-connect/userinfo"
            scope: "openid email profile"
            user_response_class: 'HWI\Bundle\OAuthBundle\OAuth\Response\PathUserResponse'
            paths:
                identifier: sub
                nickname: preferred_username
                realname: name
                email: email
```

### Configuration dans `app/config/parameters.yml`
```yaml
# app/config/parameters.yml
parameters:
    database_host: 127.0.0.1
    database_port: ~
    database_name: symfony2_sso
    database_user: root
    database_password: ~
    
    secret: ThisTokenIsNotSoSecretChangeIt
    
    keycloak_server_url: "http://localhost:8080"
    keycloak_realm: "symfony-sso"
    keycloak_client_id: "symfony2-app"
    keycloak_client_secret: "your-client-secret"
```

## 3. Configuration de Sécurité

### Fichier `app/config/security.yml`
```yaml
# app/config/security.yml
security:
    providers:
        hwi:
            id: hwi_oauth.user.provider
        
    firewalls:
        main:
            pattern: ^/
            anonymous: true
            oauth:
                resource_owners:
                    keycloak: "/login/check-keycloak"
                login_path: /login
                failure_path: /login
                oauth_user_provider:
                    service: hwi_oauth.user.provider
            logout:
                path: /logout
                target: /
                success_handler: security.logout.handler.keycloak
                
    access_control:
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/admin, roles: ROLE_USER }
        - { path: ^/profile, roles: ROLE_USER }
```

## 4. Entités et Services

### Entité User
```php
<?php
// src/AppBundle/Entity/User.php
namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;

/**
 * @ORM\Entity
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
     * @ORM\Column(type="string", length=255)
     */
    private $username;

    /**
     * @ORM\Column(type="string", length=255)
     */
    private $email;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    private $keycloakId;

    /**
     * @ORM\Column(type="json_array")
     */
    private $roles = array();

    public function getId()
    {
        return $this->id;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
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

    public function getKeycloakId()
    {
        return $this->keycloakId;
    }

    public function setKeycloakId($keycloakId)
    {
        $this->keycloakId = $keycloakId;
        return $this;
    }

    public function getRoles()
    {
        $roles = $this->roles;
        if (!in_array('ROLE_USER', $roles)) {
            $roles[] = 'ROLE_USER';
        }
        return $roles;
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
    }
}
```

### User Provider
```php
<?php
// src/AppBundle/Security/UserProvider.php
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
```

## 5. Contrôleurs

### Contrôleur principal
```php
<?php
// src/AppBundle/Controller/DefaultController.php
namespace AppBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="homepage")
     */
    public function indexAction(Request $request)
    {
        return $this->render('default/index.html.twig', [
            'user' => $this->getUser()
        ]);
    }

    /**
     * @Route("/login", name="login")
     */
    public function loginAction()
    {
        return $this->render('security/login.html.twig');
    }

    /**
     * @Route("/profile", name="profile")
     */
    public function profileAction()
    {
        $this->denyAccessUnlessGranted('ROLE_USER');
        
        return $this->render('default/profile.html.twig', [
            'user' => $this->getUser()
        ]);
    }

    /**
     * @Route("/logout", name="logout")
     */
    public function logoutAction()
    {
        // Handled by security component
    }
}
```

## 6. Templates

### Template de base
```twig
{# app/Resources/views/base.html.twig #}
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>{% block title %}Symfony 2 SSO App{% endblock %}</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    </head>
    <body>
        <nav class="navbar navbar-default">
            <div class="container">
                <div class="navbar-header">
                    <a class="navbar-brand" href="{{ path('homepage') }}">Symfony 2 SSO</a>
                </div>
                <div class="navbar-collapse">
                    <ul class="nav navbar-nav navbar-right">
                        {% if is_granted('ROLE_USER') %}
                            <li><a href="{{ path('profile') }}">Profile</a></li>
                            <li><a href="{{ path('logout') }}">Logout</a></li>
                        {% else %}
                            <li><a href="{{ path('login') }}">Login</a></li>
                        {% endif %}
                    </ul>
                </div>
            </div>
        </nav>

        <div class="container">
            {% block body %}{% endblock %}
        </div>
    </body>
</html>
```

### Page d'accueil
```twig
{# app/Resources/views/default/index.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <div class="jumbotron">
        <h1>Bienvenue sur Symfony 2 SSO</h1>
        {% if user %}
            <p>Bonjour {{ user.username }} !</p>
            <p>Vous êtes connecté via Keycloak SSO.</p>
            <a href="{{ path('profile') }}" class="btn btn-primary">Voir le profil</a>
        {% else %}
            <p>Connectez-vous pour accéder à l'application.</p>
            <a href="{{ path('login') }}" class="btn btn-primary">Se connecter</a>
        {% endif %}
    </div>
{% endblock %}
```

### Page de login
```twig
{# app/Resources/views/security/login.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <div class="row">
        <div class="col-md-4 col-md-offset-4">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">Connexion</h3>
                </div>
                <div class="panel-body">
                    <a href="{{ hwi_oauth_login_url('keycloak') }}" class="btn btn-primary btn-block">
                        Se connecter avec Keycloak
                    </a>
                </div>
            </div>
        </div>
    </div>
{% endblock %}
```

### Page de profil
```twig
{# app/Resources/views/default/profile.html.twig #}
{% extends 'base.html.twig' %}

{% block body %}
    <h2>Profil utilisateur</h2>
    <div class="panel panel-default">
        <div class="panel-body">
            <p><strong>Nom d'utilisateur:</strong> {{ user.username }}</p>
            <p><strong>Email:</strong> {{ user.email }}</p>
            <p><strong>ID Keycloak:</strong> {{ user.keycloakId }}</p>
            <p><strong>Rôles:</strong> {{ user.roles|join(', ') }}</p>
        </div>
    </div>
{% endblock %}
```

## 7. Configuration du Routing

### Fichier `app/config/routing.yml`
```yaml
# app/config/routing.yml
app:
    resource: "@AppBundle/Controller/"
    type: annotation
    prefix: /

hwi_oauth_redirect:
    resource: "@HWIOAuthBundle/Resources/config/routing/redirect.xml"
    prefix: /connect

hwi_oauth_login:
    resource: "@HWIOAuthBundle/Resources/config/routing/login.xml"
    prefix: /login
```

## 8. Services

### Configuration dans `app/config/services.yml`
```yaml
# app/config/services.yml
services:
    app.user_provider:
        class: AppBundle\Security\UserProvider
        arguments: ["@doctrine.orm.entity_manager"]

    security.logout.handler.keycloak:
        class: AppBundle\Security\KeycloakLogoutHandler
        arguments: ["%keycloak_server_url%", "%keycloak_realm%"]
```

### Handler de logout Keycloak
```php
<?php
// src/AppBundle/Security/KeycloakLogoutHandler.php
namespace AppBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

class KeycloakLogoutHandler implements LogoutSuccessHandlerInterface
{
    private $keycloakServerUrl;
    private $keycloakRealm;

    public function __construct($keycloakServerUrl, $keycloakRealm)
    {
        $this->keycloakServerUrl = $keycloakServerUrl;
        $this->keycloakRealm = $keycloakRealm;
    }

    public function onLogoutSuccess(Request $request)
    {
        $logoutUrl = sprintf(
            '%s/auth/realms/%s/protocol/openid-connect/logout',
            $this->keycloakServerUrl,
            $this->keycloakRealm
        );

        return new RedirectResponse($logoutUrl);
    }
}
```

## 9. Configuration de la Base de Données

### Création des tables
```bash
# Créer la base de données
php app/console doctrine:database:create

# Générer les migrations
php app/console doctrine:migrations:diff

# Appliquer les migrations
php app/console doctrine:migrations:migrate
```

## 10. Configuration Keycloak

### Création du client dans Keycloak
1. Accédez à l'admin console Keycloak
2. Créez un nouveau realm "symfony-sso"
3. Créez un client "symfony2-app"
4. Configurez les URLs de redirection:
    - Valid Redirect URIs: `http://localhost:8000/login/check-keycloak`
    - Base URL: `http://localhost:8000/`

## 11. Déploiement

### Serveur de développement
```bash
# Lancer le serveur de développement
php app/console server:run
```

### Configuration Apache/Nginx
Configurez votre serveur web pour pointer vers le dossier `web/` de votre application Symfony.

## 12. Test de l'Application

1. Démarrez Keycloak
2. Accédez à `http://localhost:8000`
3. Cliquez sur "Se connecter"
4. Authentifiez-vous via Keycloak
5. Vous devriez être redirigé vers l'application avec une session active

L'application est maintenant configurée pour le SSO avec Keycloak !