<?php

use App\Http\Controllers\DashboardController;
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

// Authentication routes
Route::get('/login', [AuthController::class, 'login'])->name('login');
Route::get('/auth/keycloak', [AuthController::class, 'redirectToKeycloak'])->name('auth.keycloak');
Route::get('/auth/callback', [AuthController::class, 'handleKeycloakCallback'])->name('auth.callback');
Route::get('/auth/logout', [AuthController::class, 'logout'])->name('logout');

// Protected routes
Route::middleware('auth')->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/profile', [DashboardController::class, 'profile'])->name('profile');
});

// API routes for testing
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/api/user', function () {
        return response()->json(auth()->user());
    });

    Route::get('/api/status', function () {
        return response()->json([
            'status' => 'authenticated',
            'app' => 'laravel SSO App',
            'user' => auth()->user()->name,
            'timestamp' => now()->toISOString()
        ]);
    });
});

