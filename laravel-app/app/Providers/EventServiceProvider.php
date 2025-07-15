<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event listener mappings for the application.
     * @var array[]
     */
    protected $listen = [
        \SocialiteProviders\Manager\SocialiteWasCalled::class => [
            'SocialiteProviders\\Keycloak\\KeycloakExtendSocialite@handle',
            ],
    ];

    /**
     * Register any events for this application.
     */
    public function boot(){
        parent::boot();
    }
}
