@extends('layouts.app')

@section('title', 'Accueil - Laravel SSO App')

@section('content')
    <div class="text-center">
        <h1 class="mb-4">Bienvenue sur Laravel SSO App</h1>

        @guest
            <div class="card">
                <h2>Authentification SSO</h2>
                <p>Connectez-vous pour accéder à toutes les applications du challenge multi-framework.</p>
                <a href="{{ route('auth.keycloak') }}" class="btn">Se connecter avec Keycloak</a>
            </div>
        @else
            <div class="card">
                <h2>Vous êtes connecté !</h2>
                <p>Bienvenue {{ Auth::user()->name }}, vous pouvez maintenant accéder à toutes les applications.</p>
                <a href="{{ route('dashboard') }}" class="btn">Aller au Dashboard</a>
            </div>
        @endguest

        <div class="card">
            <h2>À propos du Challenge</h2>
            <p>Cette application fait partie d'un challenge SSO multi-framework incluant :</p>
            <ul style="text-align: left; display: inline-block;">
                <li>Symfony 2 (Port 8001)</li>
                <li>Symfony 3 (Port 8002)</li>
                <li>Symfony 6 (Port 8003)</li>
                <li>Laravel (Port 8004)</li>
                <li>React App (Port 5173)</li>
            </ul>
        </div>
    </div>
@endsection
