<?php

namespace App\Providers;

use App\Services\KeycloakTokenExchangeService;
use App\Services\SymfonyApiService;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use SocialiteProviders\Keycloak\Provider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Enregistrer KeycloakTokenExchangeService en singleton
        $this->app->singleton(KeycloakTokenExchangeService::class);

        // Enregistrer SymfonyApiService avec injection de dépendance
        $this->app->singleton(SymfonyApiService::class, function ($app) {
            return new SymfonyApiService($app->make(KeycloakTokenExchangeService::class));
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Socialite::extend('keycloak', function ($app) {
            $config = $app['config']['services.keycloak'];
            return Socialite::buildProvider(Provider::class, $config);
        });
    }
}
