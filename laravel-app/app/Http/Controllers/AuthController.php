<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use App\Models\User;
use Illuminate\Support\Str;

class AuthController extends Controller
{
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

            // Find or create user
            $user = User::updateOrCreate(
                ['email' => $keycloakUser->email],
                [
                    'name' => $keycloakUser->name ?? $keycloakUser->nickname ?? $keycloakUser->email,
                    'email' => $keycloakUser->email,
                    'keycloak_id' => $keycloakUser->id,
                    'password' => bcrypt(Str::random(16)), // Random password since we use SSO
                ]
            );

            Auth::login($user);

            return redirect()->intended('/dashboard');
        } catch (\Exception $e) {
            return redirect('/login')->with('error', 'Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Logout user and redirect to keycloak logout
     */
    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        $keycloakLogoutUrl = config('services.keycloak.base_url') .
            '/realms/' . config('services.keycloak.realms') .
            '/protocol/openid-connect/logout?post_logout_redirect_uri=' .
            urlencode(url('/'));

        return redirect($keycloakLogoutUrl);
    }

    /**
     * Login form
     */
    public function login()
    {
        return view('login');
    }
}
