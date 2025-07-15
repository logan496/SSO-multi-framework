@extends('layouts.app')

@section('title', 'Profil - Laravel SSO App')

@section('content')
    <div>
        <h1 class="mb-4">Profil utilisateur</h1>

        <div class="card" style="max-width: 600px;">
            <h2>Informations personnelles</h2>

            <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 1rem; margin-bottom: 1rem;">
                <strong>Nom complet :</strong>
                <span>{{ $user->name }}</span>

                <strong>Adresse email :</strong>
                <span>{{ $user->email }}</span>

                <strong>ID Keycloak :</strong>
                <span>{{ $user->keycloak_id }}</span>

                <strong>Email vérifié :</strong>
                <span>{{ $user->email_verified_at ? '✓ Oui' : '✗ Non' }}</span>

                <strong>Compte créé :</strong>
                <span>{{ $user->created_at->format('d/m/Y H:i') }}</span>

                <strong>Dernière mise à jour :</strong>
                <span>{{ $user->updated_at->format('d/m/Y H:i') }}</span>
            </div>

            <div style="margin-top: 2rem;">
                <a href="{{ route('dashboard') }}" class="btn">Retour au Dashboard</a>
            </div>
        </div>
    </div>
@endsection
