<?php

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