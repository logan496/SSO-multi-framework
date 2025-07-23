<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class DashboardController extends Controller
{
    /**
     * Show the application dashboard
     */
    public function index(){
        $user = Auth::user();

        return view('dashboard', [
            'user' => $user,
            'apps' => [
                'Symfony 2' => 'http://localhost:8001',
                'Symfony 3' => 'http://localhost:8002/',
                'Symfony 6' => 'http://localhost:8003',
                'React App' => 'http://localhost:5173',
            ]
        ]);
    }
    /**
     * Show user profile
     */
    public function profile()
    {
        return view('profile', ['user' => Auth::user()]);
    }
}
