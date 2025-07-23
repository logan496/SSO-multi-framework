<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class RoleMiddleware
{
    /**
     * Handle an incoming request
     *
     * @param Closure(Request): (Response) $next
     */
    public function handle(Request $request, Closure $next, string $role): Response
    {
        if (!Auth::check()) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Unauthorized - Authentication required'
                ], 401);
            }
            return redirect()->route('login');
        }

        $user = Auth::user();
        $allowedRoles = array_map('trim', explode(',', $role));

        // Essayer de rafraîchir le token Keycloak si nécessaire
        if ($user->keycloak_token && !$user->hasValidKeycloakToken()) {
            $user->refreshKeycloakTokenIfNeeded();
        }

        // Vérifier si l'utilisateur a au moins un des rôles requis
        $hasRequiredRole = $user->hasAnyRole($allowedRoles);

        // Log pour debug
        Log::info('Vérification des rôles', [
            'user_id' => $user->id,
            'user_email' => $user->email,
            'required_roles' => $allowedRoles,
            'user_roles' => $user->getAllRoles(),
            'has_required_role' => $hasRequiredRole,
            'request_path' => $request->path()
        ]);

        if (!$hasRequiredRole) {
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Forbidden - Insufficient permissions',
                    'required_roles' => $allowedRoles,
                    'user_roles' => $user->getAllRoles()
                ], 403);
            }

            abort(403, 'Accès refusé. Rôles requis: ' . implode(', ', $allowedRoles));
        }

        return $next($request);
    }
}
