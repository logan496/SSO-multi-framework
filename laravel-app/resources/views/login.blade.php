@extends('layouts.app')

@section('title', 'Connexion - Laravel SSO App')

@section('content')
    <div class="text-center">
        <div class="card" style="max-width: 400px; margin: 0 auto;">
            <h2 class="mb-4">Connexion</h2>

            <p class="mb-4">Utilisez Keycloak pour vous connecter et accéder à toutes les applications du challenge.</p>

            <a href="{{ route('auth.keycloak') }}" class="btn" style="width: 100%;">
                Se connecter avec Keycloak
            </a>

            <hr style="margin: 2rem 0;">

            <p style="font-size: 0.9rem; color: #666;">
                Une fois connecté, vous pourrez accéder à toutes les applications sans ressaisir vos identifiants.
            </p>
        </div>
    </div>
@endsection
