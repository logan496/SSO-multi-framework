// SSODiagnostic.jsx - Composant pour diagnostiquer les problèmes SSO
import { useState } from 'react';
import { keycloakConfig } from '../../services/keycloak/keycloakConfig.js';

const SSODiagnostic = ({ initError, resetAndRetry }) => {
    const [diagnostics, setDiagnostics] = useState(null);
    const [testing, setTesting] = useState(false);

    const runDiagnostics = async () => {
        setTesting(true);
        const results = {
            timestamp: new Date().toISOString(),
            config: {},
            connectivity: {},
            browser: {},
            environment: {}
        };

        try {
            // 1. Vérification de la configuration
            console.log('🔍 Diagnostic - Vérification de la configuration...');
            results.config = {
                url: keycloakConfig.url || 'MANQUANT',
                realm: keycloakConfig.realm || 'MANQUANT',
                clientId: keycloakConfig.clientId || 'MANQUANT',
                isComplete: !!(keycloakConfig.url && keycloakConfig.realm && keycloakConfig.clientId)
            };

            // 2. Test de connectivité à Keycloak
            console.log('🌐 Diagnostic - Test de connectivité...');
            if (results.config.isComplete) {
                try {
                    const testUrl = `${keycloakConfig.url}/realms/${keycloakConfig.realm}/.well-known/openid_configuration`;
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 10000);

                    const response = await fetch(testUrl, {
                        method: 'GET',
                        mode: 'cors',
                        headers: { 'Accept': 'application/json' },
                        signal: controller.signal
                    });

                    clearTimeout(timeoutId);

                    results.connectivity = {
                        reachable: response.ok,
                        status: response.status,
                        statusText: response.statusText,
                        testUrl: testUrl
                    };

                    if (response.ok) {
                        const data = await response.json();
                        results.connectivity.hasOpenIdConfig = true;
                        results.connectivity.authEndpoint = data.authorization_endpoint;
                        results.connectivity.tokenEndpoint = data.token_endpoint;
                    }
                } catch (connectError) {
                    results.connectivity = {
                        reachable: false,
                        error: connectError.message,
                        errorType: connectError.name
                    };
                }
            } else {
                results.connectivity = {
                    reachable: false,
                    error: 'Configuration incomplète'
                };
            }

            // 3. Informations du navigateur
            console.log('🖥️ Diagnostic - Informations navigateur...');
            results.browser = {
                userAgent: navigator.userAgent,
                cookiesEnabled: navigator.cookieEnabled,
                localStorage: typeof(Storage) !== 'undefined',
                sessionStorage: typeof(Storage) !== 'undefined' && window.sessionStorage,
                currentUrl: window.location.href,
                origin: window.location.origin,
                protocol: window.location.protocol
            };

            // 4. Variables d'environnement
            console.log('⚙️ Diagnostic - Variables d\'environnement...');
            results.environment = {
                NODE_ENV: import.meta.env.MODE,
                DEV: import.meta.env.DEV,
                VITE_KEYCLOAK_URL: import.meta.env.VITE_KEYCLOAK_URL || 'NON DÉFINIE',
                VITE_KEYCLOAK_REALM: import.meta.env.VITE_KEYCLOAK_REALM || 'NON DÉFINIE',
                VITE_KEYCLOAK_CLIENT_ID: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'NON DÉFINIE'
            };

            // 5. Test des dépendances
            console.log('📦 Diagnostic - Dépendances...');
            results.dependencies = {
                keycloakJs: typeof window.Keycloak !== 'undefined' || 'Chargement dynamique',
                react: typeof React !== 'undefined'
            };

        } catch (error) {
            results.error = {
                message: error.message,
                stack: error.stack
            };
        }

        setDiagnostics(results);
        setTesting(false);
        console.log('📊 Résultats du diagnostic:', results);
    };

    const getDiagnosticColor = (value, type = 'boolean') => {
        if (type === 'boolean') {
            return value ? 'text-green-600' : 'text-red-600';
        }
        if (type === 'status') {
            return value >= 200 && value < 300 ? 'text-green-600' : 'text-red-600';
        }
        return 'text-gray-600';
    };

    const getRecommendations = () => {
        if (!diagnostics) return [];

        const recommendations = [];

        if (!diagnostics.config.isComplete) {
            recommendations.push({
                type: 'error',
                title: 'Configuration incomplète',
                message: 'Vérifiez que toutes les variables d\'environnement VITE_KEYCLOAK_* sont définies dans votre fichier .env'
            });
        }

        if (diagnostics.connectivity.reachable === false) {
            recommendations.push({
                type: 'error',
                title: 'Keycloak inaccessible',
                message: 'Vérifiez que votre serveur Keycloak est démarré et accessible à l\'URL configurée'
            });
        }

        if (diagnostics.browser.protocol === 'file:') {
            recommendations.push({
                type: 'warning',
                title: 'Protocole file:// détecté',
                message: 'L\'authentification SSO ne fonctionne pas avec le protocole file://. Utilisez un serveur de développement.'
            });
        }

        if (!diagnostics.browser.cookiesEnabled) {
            recommendations.push({
                type: 'warning',
                title: 'Cookies désactivés',
                message: 'Les cookies sont nécessaires pour le fonctionnement de l\'authentification SSO'
            });
        }

        return recommendations;
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <div className="bg-white rounded-lg shadow-lg">
                <div className="px-6 py-4 border-b border-gray-200">
                    <h2 className="text-xl font-semibold text-gray-900">
                        Diagnostic SSO Keycloak
                    </h2>
                    <p className="text-gray-600 mt-1">
                        Analyse des problèmes de configuration et de connectivité
                    </p>
                </div>

                <div className="p-6">
                    <div className="flex flex-col sm:flex-row gap-4 mb-6">
                        <button
                            onClick={runDiagnostics}
                            disabled={testing}
                            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {testing ? 'Diagnostic en cours...' : 'Lancer le diagnostic'}
                        </button>

                        <button
                            onClick={resetAndRetry}
                            className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                        >
                            Réessayer la connexion
                        </button>
                    </div>

                    {/* Erreur actuelle */}
                    {initError && (
                        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
                            <h3 className="text-sm font-medium text-red-800">Erreur actuelle :</h3>
                            <p className="text-sm text-red-700 mt-1">{initError}</p>
                        </div>
                    )}

                    {/* Résultats du diagnostic */}
                    {diagnostics && (
                        <div className="space-y-6">
                            {/* Recommandations */}
                            {getRecommendations().length > 0 && (
                                <div className="space-y-3">
                                    <h3 className="text-lg font-medium text-gray-900">Recommandations</h3>
                                    {getRecommendations().map((rec, index) => (
                                        <div
                                            key={index}
                                            className={`p-4 rounded-md border ${
                                                rec.type === 'error'
                                                    ? 'bg-red-50 border-red-200'
                                                    : 'bg-yellow-50 border-yellow-200'
                                            }`}
                                        >
                                            <h4 className={`font-medium ${
                                                rec.type === 'error' ? 'text-red-800' : 'text-yellow-800'
                                            }`}>
                                                {rec.title}
                                            </h4>
                                            <p className={`text-sm mt-1 ${
                                                rec.type === 'error' ? 'text-red-700' : 'text-yellow-700'
                                            }`}>
                                                {rec.message}
                                            </p>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Configuration */}
                            <div>
                                <h3 className="text-lg font-medium text-gray-900 mb-3">Configuration</h3>
                                <div className="bg-gray-50 rounded-md p-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                        <div>
                                            <span className="font-medium">URL Keycloak:</span>
                                            <span className={`ml-2 ${getDiagnosticColor(diagnostics.config.url !== 'MANQUANT')}`}>
                                                {diagnostics.config.url}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="font-medium">Realm:</span>
                                            <span className={`ml-2 ${getDiagnosticColor(diagnostics.config.realm !== 'MANQUANT')}`}>
                                                {diagnostics.config.realm}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="font-medium">Client ID:</span>
                                            <span className={`ml-2 ${getDiagnosticColor(diagnostics.config.clientId !== 'MANQUANT')}`}>
                                                {diagnostics.config.clientId}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="font-medium">Configuration complète:</span>
                                            <span className={`ml-2 ${getDiagnosticColor(diagnostics.config.isComplete)}`}>
                                                {diagnostics.config.isComplete ? '✅ Oui' : '❌ Non'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Connectivité */}
                            <div>
                                <h3 className="text-lg font-medium text-gray-900 mb-3">Connectivité Keycloak</h3>
                                <div className="bg-gray-50 rounded-md p-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                        <div>
                                            <span className="font-medium">Accessible:</span>
                                            <span className={`ml-2 ${getDiagnosticColor(diagnostics.connectivity.reachable)}`}>
                                                {diagnostics.connectivity.reachable ? '✅ Oui' : '❌ Non'}
                                            </span>
                                        </div>
                                        {diagnostics.connectivity.status && (
                                            <div>
                                                <span className="font-medium">Status HTTP:</span>
                                                <span className={`ml-2 ${getDiagnosticColor(diagnostics.connectivity.status, 'status')}`}>
                                                    {diagnostics.connectivity.status}
                                                </span>
                                            </div>
                                        )}
                                        {diagnostics.connectivity.error && (
                                            <div className="md:col-span-2">
                                                <span className="font-medium text-red-600">Erreur:</span>
                                                <span className="ml-2 text-red-600 text-xs">
                                                    {diagnostics.connectivity.error}
                                                </span>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Environnement */}
                            <div>
                                <h3 className="text-lg font-medium text-gray-900 mb-3">Variables d'environnement</h3>
                                <div className="bg-gray-50 rounded-md p-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono">
                                        {Object.entries(diagnostics.environment).map(([key, value]) => (
                                            <div key={key}>
                                                <span className="font-medium">{key}:</span>
                                                <span className={`ml-2 ${
                                                    value.includes('NON DÉFINIE') ? 'text-red-600' : 'text-green-600'
                                                }`}>
                                                    {value}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {/* Informations techniques */}
                            <details className="border border-gray-200 rounded-md">
                                <summary className="px-4 py-2 bg-gray-50 cursor-pointer font-medium">
                                    Informations techniques détaillées
                                </summary>
                                <div className="p-4 text-xs font-mono bg-gray-900 text-green-400 rounded-b-md">
                                    <pre>{JSON.stringify(diagnostics, null, 2)}</pre>
                                </div>
                            </details>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SSODiagnostic;