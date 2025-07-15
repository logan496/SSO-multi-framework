@extends('layouts.app')

@section('title', 'Dashboard - Laravel SSO App')

@section('content')
    <div>
        <h1 class="mb-4">Dashboard Laravel</h1>

        <div class="grid">
            <div class="card">
                <h2>Informations utilisateur</h2>
                <p><strong>Nom :</strong> {{ $user->name }}</p>
                <p><strong>Email :</strong> {{ $user->email }}</p>
                <p><strong>Keycloak ID :</strong> {{ $user->keycloak_id }}</p>
                <p><strong>Dernière connexion :</strong> {{ $user->updated_at->format('d/m/Y H:i') }}</p>

                <a href="{{ route('profile') }}" class="btn">Voir le profil</a>
            </div>

            <div class="card">
                <h2>Applications du Challenge</h2>
                <p>Accédez aux autres applications sans vous reconnecter :</p>

                @foreach($apps as $name => $url)
                    <div style="margin-bottom: 0.5rem;">
                        <a href="{{ $url }}" class="btn" target="_blank">{{ $name }}</a>
                    </div>
                @endforeach
            </div>

            <div class="card">
                <h2>API Endpoints</h2>
                <p>Testez les endpoints API :</p>

                <div style="margin-bottom: 0.5rem;">
                    <a href="/api/user" class="btn" target="_blank">GET /api/user</a>
                </div>
                <div style="margin-bottom: 0.5rem;">
                    <a href="/api/status" class="btn" target="_blank">GET /api/status</a>
                </div>
            </div>

            <div class="card">
                <h2>Statut SSO</h2>
                <p><strong>Statut :</strong> <span style="color: green;">✓ Connecté</span></p>
                <p><strong>Application :</strong> Laravel SSO App</p>
                <p><strong>Realm :</strong> multiframework-sso</p>
                <p><strong>Session :</strong> Active</p>
            </div>
        </div>
    </div>
@endsection
