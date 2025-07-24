import {useEffect, useState, useCallback} from "react";
import {AuthContext} from "../context/AuthContext.js";
import KeycloakService from "../services/keycloak/KeycloakService.js";

const AuthProvider = ({ children }) => {
    const [keycloakService] = useState(() => new KeycloakService());
    const [authenticated, setAuthenticated] = useState(false);
    const [loading, setLoading] = useState(true);
    const [user, setUser] = useState(null);
    const [error, setError] = useState(null);
    const [initializationAttempts, setInitializationAttempts] = useState(0);

    const initKeycloak = useCallback(async (retryCount = 0) => {
        const maxRetries = 3;

        try {
            console.log(`Tentative d'initialisation Keycloak #${retryCount + 1}`);
            setError(null);
            setLoading(true);

            const isAuthenticated = await keycloakService.init();

            console.log('Résultat authentification:', isAuthenticated);
            setAuthenticated(isAuthenticated);

            if (isAuthenticated) {
                const userProfile = keycloakService.userProfile;
                console.log('Profil utilisateur:', userProfile);
                setUser(userProfile);

                // Charger le profil complet depuis Keycloak si disponible
                try {
                    const fullProfile = await keycloakService.loadUserProfile();
                    if (fullProfile) {
                        console.log('Profil complet chargé:', fullProfile);
                        setUser(prev => ({ ...prev, ...fullProfile }));
                    }
                } catch (profileError) {
                    console.warn('Impossible de charger le profil complet:', profileError);

                }
            } else {
                setUser(null);
            }

            setInitializationAttempts(retryCount + 1);

        } catch (error) {
            console.error(`Erreur initialisation Keycloak (tentative ${retryCount + 1}):`, error);

            if (retryCount < maxRetries) {
                console.log(`Nouvelle tentative dans 2 secondes...`);
                setTimeout(() => {
                    initKeycloak(retryCount + 1);
                }, 2000);
                return;
            }

            setError(`Erreur de connexion au serveur d'authentification: ${error.message}`);
            setAuthenticated(false);
            setUser(null);
        } finally {

            if (retryCount >= maxRetries || !error) {
                setLoading(false);
            }
        }
    }, [error, keycloakService]);

    useEffect(() => {
        // Éviter les initialisations multiples
        if (initializationAttempts === 0) {
            initKeycloak();
        }
    }, [initKeycloak, initializationAttempts]);

    const login = async () => {
        try {
            setError(null);
            console.log('Tentative de connexion...');
            await keycloakService.login();
        } catch (error) {
            console.error('Erreur connexion:', error);
            setError('Erreur lors de la connexion');
        }
    };

    const logout = useCallback(() => {
        console.log('Déconnexion...');
        keycloakService.logout();
        // Les états seront réinitialisés lors de la redirection
    }, [keycloakService]);

    const retry = useCallback(() => {
        setInitializationAttempts(0);
        setError(null);
        setLoading(true);
    }, []);

    // Hook pour écouter les changements d'état du token
    useEffect(() => {
        if (!keycloakService.keycloak || !authenticated) return;

        const checkTokenValidity = () => {
            if (keycloakService.isTokenExpired()) {
                console.warn('Token expiré détecté');
                // Le rafraîchissement automatique devrait gérer cela
            }
        };

        const interval = setInterval(checkTokenValidity, 10000); // Vérifier toutes les 10 secondes

        return () => clearInterval(interval);
    }, [keycloakService, authenticated]);

    const contextValue = {
        keycloakService,
        authenticated,
        loading,
        user,
        error,
        login,
        logout,
        retry,
        initializationAttempts
    };

    return (
        <AuthContext.Provider value={contextValue}>
            {children}
        </AuthContext.Provider>
    );
};

export default AuthProvider;