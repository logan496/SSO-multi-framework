<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Dashboard - Laravel SSO App</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .header h1 {
            color: #4a5568;
            margin-bottom: 0.5rem;
            font-size: 2.5rem;
        }

        .user-badge {
            display: inline-block;
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: 600;
            margin-top: 1rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(31, 38, 135, 0.5);
        }

        .card h2 {
            color: #4a5568;
            margin-bottom: 1rem;
            font-size: 1.5rem;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 0.5rem;
        }

        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            cursor: pointer;
            margin: 0.25rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .btn.success {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }

        .btn.info {
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
        }

        .btn.warning {
            background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);
        }

        .btn.symfony {
            background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%);
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }

        .status-online {
            background: #48bb78;
            box-shadow: 0 0 10px #48bb78;
        }

        .status-offline {
            background: #f56565;
            box-shadow: 0 0 10px #f56565;
        }

        .api-response {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-family: monospace;
            font-size: 0.875rem;
            max-height: 400px;
            overflow-y: auto;
            display: none;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .role-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .role-tab {
            background: rgba(255, 255, 255, 0.3);
            border: 2px solid rgba(255, 255, 255, 0.3);
            color: white;
            padding: 1rem 2rem;
            border-radius: 25px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .role-tab.active {
            background: rgba(255, 255, 255, 0.95);
            color: #4a5568;
            border-color: rgba(255, 255, 255, 0.95);
        }

        .role-content {
            display: none;
        }

        .role-content.active {
            display: block;
        }

        .endpoint-test {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }

        .endpoint-header {
            background: #f8f9fa;
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .endpoint-method {
            background: #48bb78;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.75rem;
            font-weight: bold;
        }

        .endpoint-path {
            font-family: monospace;
            color: #4a5568;
            font-weight: 600;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .stat-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }

        .stat-label {
            font-size: 0.875rem;
            opacity: 0.9;
        }
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="header">
        <h1>Dashboard Laravel SSO</h1>
        <p>Bienvenue dans votre espace de gestion</p>
        <div class="user-badge">
            👤 {{ $user->name }} ({{ $user->email }})
        </div>
    </div>

    <!-- Role Tabs -->
    <div class="role-tabs">
        <div class="role-tab active" onclick="switchTab('general')">
            🏠 Général
        </div>
        @if(auth()->user()->hasRole('manager') || auth()->user()->hasRole('admin'))
            <div class="role-tab" onclick="switchTab('manager')">
                👥 Manager
            </div>
        @endif
        @if(auth()->user()->hasRole('admin'))
            <div class="role-tab" onclick="switchTab('admin')">
                ⚙️ Admin
            </div>
        @endif
    </div>

    <!-- General Content -->
    <div id="general-content" class="role-content active">
        <div class="grid">
            <!-- User Information -->
            <div class="card">
                <h2>👤 Informations utilisateur</h2>
                <p><strong>Nom :</strong> {{ $user->name }}</p>
                <p><strong>Email :</strong> {{ $user->email }}</p>
                <p><strong>Keycloak ID :</strong> {{ $user->keycloak_id }}</p>
                <p><strong>Dernière connexion :</strong> {{ $user->updated_at->format('d/m/Y H:i') }}</p>
                <p><strong>Rôles :</strong> {{ implode(', ', $user->roles ?? []) }}</p>

                <div style="margin-top: 1rem;">
                    <a href="{{ route('profile') }}" class="btn">Voir le profil</a>
                </div>
            </div>

            <!-- Applications -->
            <div class="card">
                <h2>🚀 Applications du Challenge</h2>
                <p>Accédez aux autres applications sans vous reconnecter :</p>

                @foreach($apps as $name => $url)
                    <div style="margin-bottom: 0.5rem;">
                        <a href="{{ $url }}" class="btn" target="_blank">{{ $name }}</a>
                    </div>
                @endforeach
            </div>

            <!-- Symfony API Integration -->
            <div class="card">
                <h2>🔗 Intégration API Symofny</h2>
                <p>Récupérez les données depuis l'application Symfony :</p>

                <div class="endpoint-test">
                    <div class="endpoint-header">
                        <div>
                            <span class="endpoint-method">GET</span>
                            <span class="endpoint-path">/api/test/symfony</span>
                        </div>
                        <button onclick="testSymfonyIntegration()" class="btn symfony">📊 Charger Données Symfony</button>
                    </div>
                </div>

                <div id="symfony-stats" style="display: none; margin-top: 1rem;">
                    <h3>📈 Statistiques des utilisateurs Symfony</h3>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <span class="stat-number" id="total-users">0</span>
                            <span class="stat-label">Total</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number" id="admin-users">0</span>
                            <span class="stat-label">Admins</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number" id="manager-users">0</span>
                            <span class="stat-label">Managers</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number" id="regular-users">0</span>
                            <span class="stat-label">Utilisateurs</span>
                        </div>
                    </div>
                </div>

            </div>


            </div>
        </div>
    </div>

    <!-- Manager Content -->
    @if(auth()->user()->hasRole('manager') || auth()->user()->hasRole('admin'))
        <div id="manager-content" class="role-content">
            <div class="grid">
                <div class="card">
                    <h2>👥 Dashboard Manager</h2>
                    <p>Accédez aux données de gestion de votre équipe</p>

                    <div class="endpoint-test">
                        <div class="endpoint-header">
                            <div>
                                <span class="endpoint-method">GET</span>
                                <span class="endpoint-path">/api/manager/dashboard</span>
                            </div>
                            <button onclick="testEndpoint('/api/manager/dashboard', 'manager-dashboard')" class="btn">Charger Dashboard</button>
                        </div>
                    </div>

                    <div id="manager-dashboard-response" class="api-response"></div>
                </div>

                <div class="card">
                    <h2>📈 Rapports Manager</h2>
                    <p>Consultez les rapports de votre équipe</p>

                    <div class="endpoint-test">
                        <div class="endpoint-header">
                            <div>
                                <span class="endpoint-method">GET</span>
                                <span class="endpoint-path">/api/manager/reports</span>
                            </div>
                            <button onclick="testEndpoint('/api/manager/reports', 'manager-reports')" class="btn">Charger Rapports</button>
                        </div>
                    </div>

                    <div id="manager-reports-response" class="api-response"></div>
                </div>

                <div class="card">
                    <h2>👥 Équipe</h2>
                    <p>Gérez votre équipe</p>

                    <div class="endpoint-test">
                        <div class="endpoint-header">
                            <div>
                                <span class="endpoint-method">GET</span>
                                <span class="endpoint-path">/api/manager/team</span>
                            </div>
                            <button onclick="testEndpoint('/api/manager/team', 'manager-team')" class="btn">Charger Équipe</button>
                        </div>
                    </div>

                    <div id="manager-team-response" class="api-response"></div>
                </div>
            </div>
        </div>
    @endif

    <!-- Admin Content -->
    @if(auth()->user()->hasRole('admin'))
        <div id="admin-content" class="role-content">
            <div class="grid">
{{--                <div class="card">--}}
{{--                    <h2>⚙️ Dashboard Admin</h2>--}}
{{--                    <p>Vue d'ensemble administrative du système</p>--}}

{{--                    <div class="endpoint-test">--}}
{{--                        <div class="endpoint-header">--}}
{{--                            <div>--}}
{{--                                <span class="endpoint-method">GET</span>--}}
{{--                                <span class="endpoint-path">/api/admin/dashboard</span>--}}
{{--                            </div>--}}
{{--                            <button onclick="testEndpoint('/api/dashboard', 'admin-dashboard')" class="btn">Charger Dashboard</button>--}}
{{--                        </div>--}}
{{--                    </div>--}}

{{--                    <div id="admin-dashboard-response" class="api-response"></div>--}}
{{--                </div>--}}

                <div class="card">
                    <h2>👥 Utilisateurs</h2>
                    <p>Gestion des utilisateurs du système</p>

                    <div class="endpoint-test">
                        <div class="endpoint-header">
                            <div>
                                <span class="endpoint-method">GET</span>
                                <span class="endpoint-path">/api/admin/users</span>
                            </div>
                            <button onclick="testEndpoint('/api/users', 'admin-users')" class="btn">Charger Utilisateurs</button>
                        </div>
                    </div>

                    <div id="admin-users-response" class="api-response"></div>
                </div>

                <div class="card">
                    <h2>🖥️ Système</h2>
                    <p>Informations système et performances</p>

                    <div class="endpoint-test">
                        <div class="endpoint-header">
                            <div>
                                <span class="endpoint-method">GET</span>
                                <span class="endpoint-path">/api/admin/system</span>
                            </div>
                            <button onclick="testEndpoint('/api/system', 'admin-system')" class="btn">Charger Infos Système</button>
                        </div>
                    </div>

                    <div id="admin-system-response" class="api-response"></div>
                </div>

{{--                <div class="card">--}}
{{--                    <h2>🔐 Permissions</h2>--}}
{{--                    <p>Gestion des permissions et rôles</p>--}}

{{--                    <div class="endpoint-test">--}}
{{--                        <div class="endpoint-header">--}}
{{--                            <div>--}}
{{--                                <span class="endpoint-method">GET</span>--}}
{{--                                <span class="endpoint-path">/api/admin/permissions</span>--}}
{{--                            </div>--}}
{{--                            <button onclick="testEndpoint('/api/admin/permissions', 'admin-permissions')" class="btn">Charger Permissions</button>--}}
{{--                        </div>--}}
{{--                    </div>--}}

{{--                    <div id="admin-permissions-response" class="api-response"></div>--}}
{{--                </div>--}}
            </div>
        </div>
    @endif
</div>

<script>
    // CSRF Token for AJAX requests
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Switch between role tabs
    function switchTab(tabName) {
        // Hide all content
        document.querySelectorAll('.role-content').forEach(content => {
            content.classList.remove('active');
        });

        // Remove active class from all tabs
        document.querySelectorAll('.role-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        // Show selected content
        document.getElementById(tabName + '-content').classList.add('active');

        // Add active class to clicked tab
        event.target.classList.add('active');
    }

    // Test Symfony Integration
    async function testSymfonyIntegration() {
        const responseDiv = document.getElementById('symfony-response');
        const statsDiv = document.getElementById('symfony-stats');

        responseDiv.style.display = 'block';
        responseDiv.innerHTML = '<div class="loading"></div> Récupération des données Symfony...';

        try {
            const response = await fetch('/api/test/symfony', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                    'Accept': 'application/json'
                },
                credentials: 'same-origin'
            });

            const result = await response.json();

            let statusColor = response.ok ? '#48bb78' : '#f56565';

            if (response.ok && result.success) {
                // Update statistics if data is available
                if (result.data && result.data.data && result.data.data.stats) {
                    const stats = result.data.data.stats;
                    document.getElementById('total-users').textContent = stats.total || 0;
                    document.getElementById('admin-users').textContent = stats.admins || 0;
                    document.getElementById('manager-users').textContent = stats.managers || 0;
                    document.getElementById('regular-users').textContent = stats.users || 0;

                    statsDiv.style.display = 'block';
                }

                responseDiv.innerHTML = `
                    <div style="color: ${statusColor}; font-weight: bold; margin-bottom: 0.5rem;">
                        ✅ Connexion Symfony réussie - ${result.message || 'Données récupérées'}
                    </div>
                    <pre>${JSON.stringify(result, null, 2)}</pre>
                `;
            } else {
                responseDiv.innerHTML = `
                    <div style="color: ${statusColor}; font-weight: bold; margin-bottom: 0.5rem;">
                        ❌ ${response.status} ${response.statusText} - ${result.message || 'Erreur inconnue'}
                    </div>
                    <pre>${JSON.stringify(result, null, 2)}</pre>
                `;
            }

        } catch (error) {
            responseDiv.innerHTML = `
                <div style="color: #f56565; font-weight: bold; margin-bottom: 0.5rem;">
                    ❌ Erreur de connexion: ${error.message}
                </div>
                <p>Vérifiez que l'application Symfony est démarrée sur le bon port.</p>
            `;
        }
    }

    // Test API endpoint
    async function testEndpoint(url, responseId) {
        const responseDiv = document.getElementById(responseId + '-response');
        responseDiv.style.display = 'block';
        responseDiv.innerHTML = '<div class="loading"></div> Chargement...';

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken,
                    'Accept': 'application/json'
                },
                credentials: 'same-origin'
            });

            const data = await response.json();

            let statusColor = response.ok ? '#48bb78' : '#f56565';

            responseDiv.innerHTML = `
                <div style="color: ${statusColor}; font-weight: bold; margin-bottom: 0.5rem;">
                    ${response.status} ${response.statusText}
                </div>
                <pre>${JSON.stringify(data, null, 2)}</pre>
            `;

        } catch (error) {
            responseDiv.innerHTML = `
                <div style="color: #f56565; font-weight: bold; margin-bottom: 0.5rem;">
                    Erreur: ${error.message}
                </div>
            `;
        }
    }

    // Check API status
    async function checkApiStatus() {
        await testEndpoint('/api/admin/api-status', 'api-status');
    }

    // Auto-refresh status every 30 seconds
    setInterval(() => {
        if (document.getElementById('api-status-response').style.display === 'block') {
            checkApiStatus();
        }
    }, 30000);

    // Initialize tooltips and interactions
    document.addEventListener('DOMContentLoaded', function() {
        // Add hover effects to cards
        document.querySelectorAll('.card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-5px)';
            });

            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
            });
        });

        // Auto-test Symfony connection on page load (optional)
        // testSymfonyIntegration();
    });
</script>
</body>
</html>
