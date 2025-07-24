import {useAuth} from "../../hooks/useAuth.js";
import {Shield, Loader, User} from "lucide-react";

const LoginPage = () => {
    const { login, loading, error } = useAuth();

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
            <div className="max-w-md w-full space-y-8 p-8">
                <div className="bg-white rounded-xl shadow-lg p-8">
                    <div className="text-center">
                        <Shield className="h-16 w-16 text-blue-600 mx-auto mb-4" />
                        <h2 className="text-3xl font-bold text-gray-900 mb-2">Connexion</h2>
                        <p className="text-gray-600 mb-8">Connectez-vous avec Keycloak</p>
                    </div>

                    {error && (
                        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
                            {error}
                        </div>
                    )}

                    <button
                        onClick={login}
                        disabled={loading}
                        className="w-full flex items-center justify-center px-4 py-3 border border-transparent rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? (
                            <Loader className="h-5 w-5 animate-spin" />
                        ) : (
                            <>
                                <User className="h-5 w-5 mr-2" />
                                Se connecter avec Keycloak
                            </>
                        )}
                    </button>

                    <div className="mt-6 text-sm text-gray-500 text-center">
                        <p>Authentification sécurisée via Keycloak</p>
                        <p className="mt-1">Vous serez redirigé vers le serveur d'authentification</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;