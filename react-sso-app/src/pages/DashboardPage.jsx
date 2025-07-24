import {useAuth} from "../hooks/useAuth.js";
import {useState} from "react";
import {Home, Settings, Users} from "lucide-react";
import {useAuthenticatedFetch} from "../hooks/useAuthenticatedFetch.js";
import Navigation from "../Components/navigation/Navigation.jsx";

const Dashboard = () => {
    const { user, keycloakService } = useAuth();
    const authenticatedFetch = useAuthenticatedFetch();
    const [apiData, setApiData] = useState(null);
    const [apiLoading, setApiLoading] = useState(false);

    const testApiCall = async () => {
        setApiLoading(true);
        try {
            // Exemple d'appel API authentifié
            const response = await authenticatedFetch('/api/user/profile');
            const data = await response.json();
            setApiData(data);
        } catch (error) {
            console.error('Erreur API:', error);
            setApiData({ error: error.message });
        } finally {
            setApiLoading(false);
        }
    };

    const menuItems = [
        { icon: Home, label: 'Accueil', description: 'Vue d\'ensemble' },
        { icon: Settings, label: 'Paramètres', description: 'Configuration' },
        {
            icon: Users,
            label: 'Administration',
            description: 'Gestion des utilisateurs',
            requiresRole: 'admin'
        }
    ];

    return (
        <div className="min-h-screen bg-gray-50">
            <Navigation />

            <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                <div className="px-4 py-6 sm:px-0">
                    <div className="mb-8">
                        <h1 className="text-3xl font-bold text-gray-900">
                            Bienvenue, {user?.firstName || user?.username} !
                        </h1>
                        <p className="text-gray-600 mt-2">
                            Authentification Keycloak active
                        </p>
                    </div>

                    {/* Informations utilisateur et session */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                        {/* Profil utilisateur */}
                        <div className="bg-white rounded-lg shadow p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">Profil utilisateur</h3>
                            <div className="space-y-3">
                                <div>
                                    <span className="text-sm font-medium text-gray-500">ID:</span>
                                    <p className="text-gray-900 text-sm font-mono">{user?.id}</p>
                                </div>
                                <div>
                                    <span className="text-sm font-medium text-gray-500">Nom d'utilisateur:</span>
                                    <p className="text-gray-900">{user?.username}</p>
                                </div>
                                <div>
                                    <span className="text-sm font-medium text-gray-500">Email:</span>
                                    <p className="text-gray-900">{user?.email}</p>
                                </div>
                            </div>
                        </div>

                        {/* Rôles */}
                        <div className="bg-white rounded-lg shadow p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">Rôles</h3>
                            <div className="space-y-3">
                                <div>
                                    <span className="text-sm font-medium text-gray-500">Rôles Realm:</span>
                                    <div className="flex flex-wrap gap-2 mt-1">
                                        {user?.roles?.map(role => (
                                            <span
                                                key={role}
                                                className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full"
                                            >
                        {role}
                      </span>
                                        ))}
                                    </div>
                                </div>
                                {Object.keys(user?.clientRoles || {}).length > 0 && (
                                    <div>
                                        <span className="text-sm font-medium text-gray-500">Rôles Client:</span>
                                        <div className="mt-1 space-y-1">
                                            {Object.entries(user?.clientRoles || {}).map(([client, roles]) => (
                                                <div key={client} className="text-xs">
                                                    <span className="font-medium text-gray-600">{client}:</span>
                                                    <div className="flex flex-wrap gap-1 mt-1">
                                                        {roles.roles?.map(role => (
                                                            <span
                                                                key={role}
                                                                className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full"
                                                            >
                                {role}
                              </span>
                                                        ))}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Informations de session */}
                        <div className="bg-white rounded-lg shadow p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">Session</h3>
                            <div className="space-y-3">
                                <div>
                                    <span className="text-sm font-medium text-gray-500">Statut:</span>
                                    <div className="flex items-center mt-1">
                                        <div className="h-2 w-2 bg-green-500 rounded-full mr-2"></div>
                                        <span className="text-green-600 font-medium">Connecté</span>
                                    </div>
                                </div>
                                <div>
                                    <span className="text-sm font-medium text-gray-500">Token expiré:</span>
                                    <p className={`font-medium ${keycloakService.isTokenExpired() ? 'text-red-600' : 'text-green-600'}`}>
                                        {keycloakService.isTokenExpired() ? 'Oui' : 'Non'}
                                    </p>
                                </div>
                                <div>
                                    <button
                                        onClick={testApiCall}
                                        disabled={apiLoading}
                                        className="w-full px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
                                    >
                                        {apiLoading ? 'Test...' : 'Test API Auth'}
                                    </button>
                                    {apiData && (
                                        <div className="mt-2 p-2 bg-gray-100 rounded text-xs">
                                            <pre>{JSON.stringify(apiData, null, 2)}</pre>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Menu d'actions */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {menuItems.map((item, index) => {
                            const isAccessible = !item.requiresRole || keycloakService.hasRole(item.requiresRole);

                            return (
                                <div
                                    key={index}
                                    className={`bg-white rounded-lg shadow p-6 transition-colors ${
                                        isAccessible
                                            ? 'hover:bg-gray-50 cursor-pointer'
                                            : 'opacity-50 cursor-not-allowed'
                                    }`}
                                >
                                    <div className="flex items-center mb-3">
                                        <item.icon className={`h-6 w-6 mr-3 ${
                                            isAccessible ? 'text-blue-600' : 'text-gray-400'
                                        }`} />
                                        <h3 className="text-lg font-semibold text-gray-900">
                                            {item.label}
                                        </h3>
                                    </div>
                                    <p className="text-gray-600 text-sm">{item.description}</p>
                                    {!isAccessible && (
                                        <p className="text-red-500 text-xs mt-2">
                                            Rôle requis: {item.requiresRole}
                                        </p>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            </main>
        </div>
    );
};

export default Dashboard