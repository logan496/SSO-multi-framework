<?php

use App\Http\Controllers\AdminDashboardController;
use App\Http\Controllers\FreeController;
use App\Http\Controllers\ManagerDashboardController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Note: These routes are automatically prefixed with /api/ by Laravel
// and have the 'api' middleware group applied



Route::middleware(['web', 'auth'])->group(function () {

    // Routes API de base pour tous les utilisateurs authentifiés
    Route::get('/user', function (Request $request) {
        return response()->json($request->user());
    });

    Route::get('/status', function () {
        $user = auth()->user();
        return response()->json([
            'status' => 'authenticated',
            'app' => 'Laravel SSO App',
            'user' => $user->name,
            'roles' => $user->roles ?? [],
            'timestamp' => now()->toISOString()
        ]);
    });

    Route::get('/dashboard', [AdminDashboardController::class, 'dashboard']);
    Route::get('/users', [AdminDashboardController::class, 'users']);
    Route::get('/system', [AdminDashboardController::class, 'system']);
    Route::get('/permissions', [AdminDashboardController::class, 'permissions']);
    Route::get('/test/symfony', [FreeController::class, 'test'])->name('test');

    Route::get('/dashboard', [ManagerDashboardController::class, 'dashboard']);
    Route::get('/reports', [ManagerDashboardController::class, 'reports']);
    Route::get('/team', [ManagerDashboardController::class, 'team']);
    Route::get('/api-status', [AdminDashboardController::class, 'apiStatus']);



});
