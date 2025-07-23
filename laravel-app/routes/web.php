<?php

use App\Http\Controllers\AdminDashboardController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\FreeController;
use App\Http\Controllers\ManagerDashboardController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
// Dans routes/web.php
Route::get('/debug/keycloak-token-exchange', function() {
    $service = app(App\Services\KeycloakTokenExchangeService::class);
    return response()->json($service->diagnoseTokenExchange());
});

// Authentication routes
Route::get('/login', [AuthController::class, 'login'])->name('login');
Route::get('/auth/keycloak', [AuthController::class, 'redirectToKeycloak'])->name('auth.keycloak');
Route::get('/auth/callback', [AuthController::class, 'handleKeycloakCallback'])->name('auth.callback');
Route::get('/auth/logout', [AuthController::class, 'logout'])->name('logout');


// Protected routes
Route::middleware(['auth'])->group(function () {

    // Route pour synchroniser les rôles
    Route::post('/sync-roles', [AuthController::class, 'syncRoles'])->name('sync-roles');

    // User routes (routes générales pour tous les utilisateurs authentifiés)
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/profile', [DashboardController::class, 'profile'])->name('profile');

    // Admin routes - PAGES WEB (retournent des vues HTML)
    Route::middleware(['role:admin'])->prefix('admin')->name('admin.')->group(function () {
        // Créer une route qui retourne une vue pour le dashboard admin
        Route::get('/dashboard', function() {
            return view('admin.dashboard');
        })->name('dashboard');

        // Ou si vous avez un contrôleur spécifique pour les vues admin
        // Route::get('/dashboard', [AdminDashboardController::class, 'dashboardView'])->name('dashboard');
    });

    // Manager routes - PAGES WEB (retournent des vues HTML)
    Route::middleware(['role:manager,admin'])->prefix('manager')->name('manager.')->group(function () {
        // Créer une route qui retourne une vue pour le dashboard manager
        Route::get('/dashboard', function() {
            return view('manager.dashboard');
        })->name('dashboard');

        // Ou si vous avez un contrôleur spécifique pour les vues manager
        // Route::get('/dashboard', [ManagerDashboardController::class, 'dashboardView'])->name('dashboard');
    });
});
