import React from 'react';
import { useAuth } from '../../hooks/useAuth'; // Ajustez le chemin selon votre structure
import LoadingScreen from '../common/LoadingScreen';
import ErrorDisplay from '../common/ErrorDisplay';
import LoginPage from '../auth/LoginPage';

const ProtectedRoute = ({ children, roles = [], clientRoles = {} }) => {
    const { authenticated, loading, error, keycloakService, retry } = useAuth();

    // Écran de chargement pendant l'initialisation
    if (loading) {
        return <LoadingScreen />;
    }

    // Affichage des erreurs
    if (error) {
        return <ErrorDisplay error={error} onRetry={retry} />;
    }

    // Redirection vers login si non authentifié
    if (!authenticated) {
        return <LoginPage />;
    }

    // Vérification des rôles realm
    if (roles.length > 0 && !roles.some(role => keycloakService.hasRole(role))) {
        return <AccessDenied requiredRoles={roles} />;
    }

    // Vérification des rôles client
    for (const [clientId, requiredRoles] of Object.entries(clientRoles)) {
        if (!requiredRoles.some(role => keycloakService.hasClientRole(clientId, role))) {
            return <AccessDenied requiredClientRoles={{ [clientId]: requiredRoles }} />;
        }
    }

    // Utilisateur authentifié et autorisé
    return children;
};

// // Composant d'écran de chargement
// const LoadingScreen = () => (
//     <div className="min-h-screen flex items-center justify-center bg-gray-50">
//         <div className="text-center">
//             <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
//             <h2 className="text-xl font-semibold text-gray-900 mb-2">Initialisation...</h2>
//             <p className="text-gray-600">Connexion au serveur d'authentification</p>
//         </div>
//     </div>
// );
//
// // Composant d'affichage d'erreur
// const ErrorDisplay = ({ error, onRetry }) => (
//     <div className="min-h-screen flex items-center justify-center bg-gray-50">
//         <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8 text-center">
//             <div className="h-16 w-16 text-red-500 mx-auto mb-4 flex items-center justify-center">
//                 <svg className="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 18.5c-.77.833.192 2.5 1.732 2.5z" />
//                 </svg>
//             </div>
//             <h2 className="text-2xl font-bold text-gray-900 mb-4">Erreur d'authentification</h2>
//             <p className="text-gray-600 mb-6">{error}</p>
//             <button
//                 onClick={onRetry}
//                 className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
//             >
//                 Réessayer
//             </button>
//         </div>
//     </div>
// );

// Composant de page de connexion
// const LoginPage = () => {
//     const { login, loading: loginLoading, error } = useAuth();
//
//     return (
//         <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
//             <div className="max-w-md w-full space-y-8 p-8">
//                 <div className="bg-white rounded-xl shadow-lg p-8">
//                     <div className="text-center">
//                         <div className="h-16 w-16 text-blue-600 mx-auto mb-4 flex items-center justify-center">
//                             <svg className="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//                                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
//                             </svg>
//                         </div>
//                         <h2 className="text-3xl font-bold text-gray-900 mb-2">Connexion</h2>
//                         <p className="text-gray-600 mb-8">Connectez-vous avec Keycloak</p>
//                     </div>
//
//                     {error && (
//                         <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
//                             {error}
//                         </div>
//                     )}
//
//                     <button
//                         onClick={login}
//                         disabled={loginLoading}
//                         className="w-full flex items-center justify-center px-4 py-3 border border-transparent rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
//                     >
//                         {loginLoading ? (
//                             <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
//                         ) : (
//                             <>
//                                 <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//                                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
//                                 </svg>
//                                 Se connecter avec Keycloak
//                             </>
//                         )}
//                     </button>
//
//                     <div className="mt-6 text-sm text-gray-500 text-center">
//                         <p>Authentification sécurisée via Keycloak</p>
//                         <p className="mt-1">Vous serez redirigé vers le serveur d'authentification</p>
//                     </div>
//                 </div>
//             </div>
//         </div>
//     );
// };

// Composant d'accès refusé
const AccessDenied = ({ requiredRoles = [], requiredClientRoles = {} }) => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8 text-center">
            <div className="h-16 w-16 text-red-500 mx-auto mb-4 flex items-center justify-center">
                <svg className="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Accès refusé</h2>
            <p className="text-gray-600 mb-4">Vous n'avez pas les permissions requises pour accéder à cette page.</p>

            {requiredRoles.length > 0 && (
                <div className="mb-4">
                    <p className="text-sm font-medium text-gray-700 mb-2">Rôles requis :</p>
                    <div className="flex flex-wrap gap-2 justify-center">
                        {requiredRoles.map(role => (
                            <span key={role} className="px-2 py-1 bg-red-100 text-red-800 text-xs rounded-full">
                                {role}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {Object.keys(requiredClientRoles).length > 0 && (
                <div className="mb-4">
                    <p className="text-sm font-medium text-gray-700 mb-2">Rôles client requis :</p>
                    {Object.entries(requiredClientRoles).map(([clientId, roles]) => (
                        <div key={clientId} className="mb-2">
                            <p className="text-xs text-gray-600">{clientId}:</p>
                            <div className="flex flex-wrap gap-1 justify-center">
                                {roles.map(role => (
                                    <span key={role} className="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded-full">
                                        {role}
                                    </span>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    </div>
);

export default ProtectedRoute;