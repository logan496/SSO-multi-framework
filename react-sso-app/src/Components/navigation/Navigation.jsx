import {useAuth} from "../../hooks/useAuth.js";
import {Shield, User, LogOut} from "lucide-react";

const Navigation = () => {
    const { user, logout, keycloakService } = useAuth();

    return (
        <nav className="bg-white shadow-sm border-b">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between h-16">
                    <div className="flex items-center">
                        <Shield className="h-8 w-8 text-blue-600 mr-3" />
                        <span className="text-xl font-semibold text-gray-900">Mon App Keycloak</span>
                    </div>

                    <div className="flex items-center space-x-4">
                        <div className="flex items-center text-sm text-gray-700">
                            <User className="h-4 w-4 mr-2" />
                            <span>{user?.firstName || user?.username} {user?.lastName}</span>
                            {keycloakService.isTokenExpired() && (
                                <span className="ml-2 px-2 py-1 bg-yellow-100 text-yellow-800 text-xs rounded-full">
                  Token expiré
                </span>
                            )}
                        </div>

                        <button
                            onClick={logout}
                            className="flex items-center px-3 py-2 text-sm text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors"
                        >
                            <LogOut className="h-4 w-4 mr-2" />
                            Déconnexion
                        </button>
                    </div>
                </div>
            </div>
        </nav>
    );
};

export default Navigation