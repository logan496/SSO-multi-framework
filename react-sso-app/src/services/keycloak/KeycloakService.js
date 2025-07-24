import {keycloakConfig} from "./keycloakConfig.js";

class KeycloakService {
    constructor() {
        this.keycloak = null;
        this.initialized = false;
        this.initializing = false;
        this.refreshInterval = null;
    }

    async init() {
        // Éviter les initialisations multiples
        if (this.initializing) {
            console.log('Initialisation déjà en cours...');
            return this.authenticated;
        }

        if (this.initialized) {
            console.log('Keycloak déjà initialisé');
            return this.authenticated;
        }

        try {
            this.initializing = true;
            console.log('Début initialisation Keycloak...');

            const Keycloak = (await import('keycloak-js')).default;
            this.keycloak = new Keycloak(keycloakConfig);

            // Configuration simplifiée sans silent SSO pour éviter les erreurs
            const authenticated = await this.keycloak.init({
                onLoad: 'check-sso',
                pkceMethod: 'S256',
                checkLoginIframe: false,
                redirectUri: window.location.origin,
                responseMode: 'fragment',
                // Désactiver complètement le silent SSO
                silentCheckSsoRedirectUri: undefined,
                silentCheckSsoFallback: false
            });

            this.initialized = true;
            console.log('Keycloak initialisé avec succès, authentifié:', authenticated);

            // Nettoyer l'URL après authentification
            this.cleanUrlAfterAuth();

            if (authenticated) {
                this.setupTokenRefresh();
                console.log('Utilisateur authentifié:', this.userProfile);
            } else {
                console.log('Utilisateur non authentifié - affichage du login requis');
            }

            return authenticated;
        } catch (error) {
            console.error('Keycloak init error:', error);
            this.initialized = false;

            // Si l'erreur est liée au SSO, on peut quand même continuer
            if (error.message && error.message.includes('login_required')) {
                console.log('SSO non disponible, utilisateur devra se connecter manuellement');
                this.initialized = true;
                return false;
            }

            throw error;
        } finally {
            this.initializing = false;
        }
    }

    cleanUrlAfterAuth() {
        const url = new URL(window.location.href);
        const params = url.searchParams;
        let hasAuthParams = false;

        // Supprimer les paramètres OAuth2 de l'URL
        ['code', 'state', 'session_state', 'error', 'error_description'].forEach(param => {
            if (params.has(param)) {
                hasAuthParams = true;
                params.delete(param);
            }
        });

        // Ne modifier l'URL que si nécessaire
        if (hasAuthParams) {
            const newUrl = `${url.pathname}${params.toString() ? '?' + params.toString() : ''}`;
            console.log('Nettoyage URL après auth:', window.location.href, '->', window.location.origin + newUrl);
            window.history.replaceState({}, '', newUrl);
        }
    }

    setupTokenRefresh() {
        // Nettoyer l'ancien interval s'il existe
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }

        this.refreshInterval = setInterval(async () => {
            try {
                // Vérifier si le token expire dans les 30 prochaines secondes
                const refreshed = await this.keycloak.updateToken(30);
                if (refreshed) {
                    console.log('Token rafraîchi avec succès');
                }
            } catch (error) {
                console.error('Erreur rafraîchissement token:', error);
                console.log('Token expiré, redirection vers logout...');
                this.logout();
            }
        }, 60000); // Vérifier toutes les minutes
    }

    async login() {
        if (!this.keycloak) {
            throw new Error('Keycloak non initialisé');
        }

        try {
            console.log('Début login...');

            // Nettoyer l'URL avant la redirection
            this.cleanUrlParameters();

            return await this.keycloak.login({
                redirectUri: window.location.origin,
                prompt: 'login'
            });
        } catch (error) {
            console.error('Erreur lors du login:', error);
            throw error;
        }
    }

    logout() {
        if (!this.keycloak) return;

        console.log('Début logout...');

        // Nettoyer les intervals
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }

        // Réinitialiser les flags
        this.initialized = false;
        this.initializing = false;

        // Nettoyer l'URL avant logout
        this.cleanUrlParameters();

        this.keycloak.logout({
            redirectUri: window.location.origin
        });
    }

    cleanUrlParameters() {
        const url = new URL(window.location.href);
        const params = url.searchParams;
        let hasParams = false;

        // Supprimer tous les paramètres liés à l'auth
        ['code', 'state', 'session_state', 'error', 'error_description'].forEach(param => {
            if (params.has(param)) {
                hasParams = true;
                params.delete(param);
            }
        });

        if (hasParams) {
            const newUrl = `${url.pathname}${params.toString() ? '?' + params.toString() : ''}`;
            window.history.replaceState({}, '', newUrl);
        }
    }

    get authenticated() {
        return this.keycloak?.authenticated || false;
    }

    get token() {
        return this.keycloak?.token;
    }

    get refreshToken() {
        return this.keycloak?.refreshToken;
    }

    get userProfile() {
        if (!this.keycloak?.tokenParsed) return null;

        return {
            id: this.keycloak.subject,
            username: this.keycloak.tokenParsed.preferred_username,
            email: this.keycloak.tokenParsed.email,
            firstName: this.keycloak.tokenParsed.given_name,
            lastName: this.keycloak.tokenParsed.family_name,
            fullName: this.keycloak.tokenParsed.name,
            roles: this.keycloak.realmAccess?.roles || [],
            clientRoles: this.keycloak.resourceAccess || {},
            issuedAt: new Date(this.keycloak.tokenParsed.iat * 1000),
            expiresAt: new Date(this.keycloak.tokenParsed.exp * 1000),
        };
    }

    hasRole(role) {
        return this.keycloak?.hasRealmRole(role) || false;
    }

    hasClientRole(clientId, role) {
        return this.keycloak?.hasResourceRole(role, clientId) || false;
    }

    isTokenExpired() {
        return this.keycloak?.isTokenExpired() || false;
    }

    async loadUserProfile() {
        if (!this.keycloak || !this.authenticated) return null;

        try {
            return await this.keycloak.loadUserProfile();
        } catch (error) {
            console.error('Erreur chargement profil:', error);
            return null;
        }
    }

    getAuthorizationHeader() {
        return this.token ? `Bearer ${this.token}` : null;
    }

    isConfigured() {
        return this.initialized && this.keycloak !== null;
    }

    getDebugInfo() {
        if (!this.keycloak) return { error: 'Keycloak non initialisé' };

        const tokenParsed = this.keycloak.tokenParsed;
        const currentUrl = new URL(window.location.href);

        return {
            authenticated: this.authenticated,
            initialized: this.initialized,
            initializing: this.initializing,
            hasToken: !!this.token,
            hasRefreshToken: !!this.refreshToken,
            tokenExpired: this.isTokenExpired(),
            realm: this.keycloak.realm,
            clientId: this.keycloak.clientId,
            authServerUrl: this.keycloak.authServerUrl,
            tokenIssuedAt: tokenParsed ? new Date(tokenParsed.iat * 1000).toLocaleString() : null,
            tokenExpiresAt: tokenParsed ? new Date(tokenParsed.exp * 1000).toLocaleString() : null,
            tokenTimeLeft: tokenParsed ? Math.max(0, tokenParsed.exp - Math.floor(Date.now() / 1000)) : null,
            currentUrl: window.location.href,
            hasAuthParams: currentUrl.searchParams.has('code') || currentUrl.searchParams.has('error')
        };
    }

    async forceTokenRefresh() {
        if (!this.keycloak || !this.authenticated) {
            throw new Error('Non authentifié');
        }

        try {
            const refreshed = await this.keycloak.updateToken(-1);
            console.log('Token forcé à être rafraîchi:', refreshed);
            return refreshed;
        } catch (error) {
            console.error('Erreur lors du rafraîchissement forcé:', error);
            throw error;
        }
    }
}

export default KeycloakService;