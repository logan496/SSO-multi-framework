<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use App\Models\User;
use App\Services\KeycloakService;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    protected KeycloakService $keycloakService;

    public function __construct(KeycloakService $keycloakService)
    {
        $this->keycloakService = $keycloakService;
    }

    /**
     * Redirect to keycloak for authentication
     */
    public function redirectToKeycloak()
    {
        return Socialite::driver('keycloak')->redirect();
    }

    /**
     * Handle callback from Keycloak
     */
    public function handleKeycloakCallback()
    {
        try {
            $keycloakUser = Socialite::driver('keycloak')->user();

            // Récupérer le token d'accès et les informations supplémentaires
            $accessToken = $keycloakUser->token;
            $refreshToken = $keycloakUser->refreshToken;
            $expiresIn = $keycloakUser->expiresIn ?? 3600;

            // Extraire les rôles depuis le token Keycloak
            $keycloakRoles = $this->keycloakService->getUserRoles($accessToken);

            // Si aucun rôle n'est trouvé dans Keycloak, assigner un rôle par défaut
            if (empty($keycloakRoles)) {
                $keycloakRoles = ['user']; // Rôle par défaut
                Log::info('Aucun rôle trouvé dans Keycloak pour l\'utilisateur, attribution du rôle "user" par défaut', [
                    'email' => $keycloakUser->email,
                    'keycloak_id' => $keycloakUser->id
                ]);
            }

            Log::info('Rôles extraits de Keycloak', [
                'email' => $keycloakUser->email,
                'roles' => $keycloakRoles
            ]);

            // Find or create user
            $user = User::updateOrCreate(
                ['email' => $keycloakUser->email],
                [
                    'name' => $keycloakUser->name ?? $keycloakUser->nickname ?? $keycloakUser->email,
                    'email' => $keycloakUser->email,
                    'keycloak_id' => $keycloakUser->id,
                    'keycloak_token' => $accessToken,
                    'keycloak_refresh_token' => $refreshToken,
                    'keycloak_token_expires_at' => now()->addSeconds($expiresIn),
                    'roles' => $keycloakRoles, // Assigner les rôles Keycloak
                    'password' => bcrypt(Str::random(16)), // Random password since we use SSO
                ]
            );

            // Si l'utilisateur existait déjà, mettre à jour ses rôles
            if ($user->wasRecentlyCreated === false) {
                // Fusionner les rôles existants avec les nouveaux rôles Keycloak
                $existingRoles = $user->roles ?? [];
                $mergedRoles = array_unique(array_merge($existingRoles, $keycloakRoles));

                $user->update([
                    'keycloak_token' => $accessToken,
                    'keycloak_refresh_token' => $refreshToken,
                    'keycloak_token_expires_at' => now()->addSeconds($expiresIn),
                    'roles' => $mergedRoles
                ]);

                Log::info('Rôles utilisateur mis à jour', [
                    'user_id' => $user->id,
                    'old_roles' => $existingRoles,
                    'keycloak_roles' => $keycloakRoles,
                    'merged_roles' => $mergedRoles
                ]);
            } else {
                Log::info('Nouvel utilisateur créé avec les rôles Keycloak', [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'roles' => $keycloakRoles
                ]);
            }

            // Sauvegarder les données OAuth en session pour le logout
            session([
                'oauth_data' => [
                    'access_token' => $accessToken,
                    'refresh_token' => $refreshToken,
                    'id_token' => $keycloakUser->id_token ?? null,
                ]
            ]);

            Auth::login($user);

            // Redirection basée sur le rôle de l'utilisateur
            return $this->redirectBasedOnRole($user);

        } catch (\Exception $e) {
            Log::error('Erreur lors de l\'authentification Keycloak', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return redirect('/login')->with('error', 'Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Rediriger l'utilisateur selon son rôle principal
     */
    protected function redirectBasedOnRole(User $user): \Illuminate\Http\RedirectResponse
    {
        return redirect()->route('dashboard');
    }

    /**
     * Synchroniser les rôles utilisateur avec Keycloak
     */
    public function syncRoles(Request $request)
    {
        try {
            $user = Auth::user();

            if (!$user->hasValidKeycloakToken()) {
                // Essayer de rafraîchir le token
                if (!$user->refreshKeycloakTokenIfNeeded()) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Token Keycloak invalide et impossible à rafraîchir'
                    ], 401);
                }
            }

            // Récupérer les rôles actuels depuis Keycloak
            $keycloakRoles = $this->keycloakService->getUserRoles($user->keycloak_token);

            if (empty($keycloakRoles)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Impossible de récupérer les rôles depuis Keycloak'
                ], 400);
            }

            // Mettre à jour les rôles de l'utilisateur
            $user->update(['roles' => $keycloakRoles]);

            Log::info('Rôles synchronisés avec succès', [
                'user_id' => $user->id,
                'email' => $user->email,
                'new_roles' => $keycloakRoles
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Rôles synchronisés avec succès',
                'roles' => $keycloakRoles
            ]);

        } catch (\Exception $e) {
            Log::error('Erreur lors de la synchronisation des rôles', [
                'user_id' => Auth::id(),
                'error' => $e->getMessage()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Erreur lors de la synchronisation des rôles'
            ], 500);
        }
    }

    /**
     * Logout user and redirect to keycloak logout
     */
    public function logout(Request $request)
    {
        try {
            $user = Auth::user();

            // Déconnecter de Keycloak si possible
            if ($user && $user->keycloak_refresh_token) {
                $this->keycloakService->logout($user->keycloak_refresh_token);
            }

            // Récupérer les données de session OAuth
            $oauthData = $request->session()->get('oauth_data');
            $idToken = $oauthData['id_token'] ?? null;

            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            if ($idToken) {
                $keycloakLogoutUrl = config('services.keycloak.base_url') .
                    '/realms/' . config('services.keycloak.realm') .
                    '/protocol/openid-connect/logout?' .
                    http_build_query([
                        'post_logout_redirect_uri' => url('/'),
                        'id_token_hint' => $idToken
                    ]);

                return redirect($keycloakLogoutUrl);
            }

            return redirect('/');

        } catch (\Exception $e) {
            Log::error('Erreur lors de la déconnexion', [
                'error' => $e->getMessage()
            ]);

            // Forcer la déconnexion locale même en cas d'erreur
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect('/');
        }
    }

    /**
     * Login form
     */
    public function login()
    {
        return view('login');
    }
}
