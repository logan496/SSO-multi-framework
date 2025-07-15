<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Laravel SSO App')</title>

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.bunny.net">
    <link href="https://fonts.bunny.net/css?family=figtree:400,500,600&display=swap" rel="stylesheet" />

    <!-- Scripts -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])

    <style>
        body { font-family: 'Figtree', sans-serif; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #1f2937; color: white; padding: 1rem 0; margin-bottom: 2rem; }
        .btn { padding: 0.5rem 1rem; background: #3b82f6; color: white; text-decoration: none; border-radius: 0.25rem; display: inline-block; }
        .btn:hover { background: #2563eb; }
        .btn-danger { background: #dc2626; }
        .btn-danger:hover { background: #b91c1c; }
        .card { background: white; padding: 2rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .text-center { text-align: center; }
        .mb-4 { margin-bottom: 1rem; }
        .alert { padding: 1rem; margin-bottom: 1rem; border-radius: 0.25rem; }
        .alert-error { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
        .alert-success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    </style>
</head>
<body class="font-sans antialiased">
<div class="header">
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1><a href="/" style="color: white; text-decoration: none;">Laravel SSO App</a></h1>
            <div>
                @auth
                    <span>Bonjour, {{ Auth::user()->name }}</span>
                    <a href="{{ route('dashboard') }}" class="btn" style="margin-left: 1rem;">Dashboard</a>
                    <form method="POST" action="{{ route('logout') }}" style="display: inline; margin-left: 1rem;">
                        @csrf
                        <button type="submit" class="btn btn-danger">Déconnexion</button>
                    </form>
                @else
                    <a href="{{ route('login') }}" class="btn">Connexion</a>
                @endauth
            </div>
        </div>
    </div>
</div>

<div class="container">
    @if(session('error'))
        <div class="alert alert-error">{{ session('error') }}</div>
    @endif

    @if(session('success'))
        <div class="alert alert-success">{{ session('success') }}</div>
    @endif

    @yield('content')
</div>
</body>
</html>
