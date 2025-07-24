import {useEffect, useState, useCallback, useRef} from "react";
import {AuthContext} from "../context/AuthContext.js";
import KeycloakService from "../services/keycloak/KeycloakService.js";

const AuthProvider = ({ children }) => {
    const [keycloakService] = useState(() => new KeycloakService());
    const [authenticated, setAuthenticated] = useState(false);
    const [loading, setLoading] = useState(true);
    const [user, setUser] = useState(null);
    const [error, setError] = useState(null);

    // Utiliser useRef pour éviter les re-initialisations
    const initializationRef = useRef({
        attempts: 0,
        isInitializing: false,
        initialized: false
    });

    const initKeycloak = useCallback(async (retryCount = 0) => {
        const maxRetries = 3;

        // Éviter les initialisations multiples simultanées
        if (initializationRef.current.isInitializing) {
            console.log('Initialisation déjà en cours, ignore...');
            return;
        }

        // Si déjà initialisé avec succès, ne pas réinitialiser
        if (initializationRef.current.initialized && retryCount === 0) {
            console.log('Keycloak déjà initialisé avec succès');
            return;
        }

        try {
            console.log(`Tentative d'initialisation Keycloak #${retryCount + 1}`);
            initializationRef.current.isInitializing = true;
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

            // Marquer comme initialisé avec succès
            initializationRef.current.initialized = true;
            initializationRef.current.attempts = retryCount + 1;

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
            initializationRef.current.isInitializing = false;
            // Ne pas mettre loading à false si on va réessayer
            if (retryCount >= maxRetries || !error) {
                setLoading(false);
            }
        }
    }, [keycloakService]);

    // Effect d'initialisation - ne s'exécute qu'une seule fois
    useEffect(() => {
        // Éviter les initialisations multiples
        if (initializationRef.current.attempts === 0 && !initializationRef.current.isInitializing) {
            initKeycloak();
        }
    }, []); // Dépendances vides pour ne s'exécuter qu'au mount

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
        // Réinitialiser les refs
        initializationRef.current = {
            attempts: 0,
            isInitializing: false,
            initialized: false
        };
        keycloakService.logout();
    }, [keycloakService]);

    const retry = useCallback(() => {
        initializationRef.current = {
            attempts: 0,
            isInitializing: false,
            initialized: false
        };
        setError(null);
        setLoading(true);
        initKeycloak();
    }, [initKeycloak]);

    // Hook pour écouter les changements d'état du token
    useEffect(() => {
        if (!keycloakService.keycloak || !authenticated) return;

        const checkTokenValidity = () => {
            if (keycloakService.isTokenExpired()) {
                console.warn('Token expiré détecté');
            }
        };

        const interval = setInterval(checkTokenValidity, 30000); // Vérifier toutes les 30 secondes

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
        initializationAttempts: initializationRef.current.attempts
    };

    return (
        <AuthContext.Provider value={contextValue}>
            {children}
        </AuthContext.Provider>
    );
};

export default AuthProvider;