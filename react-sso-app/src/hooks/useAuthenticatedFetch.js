import {useAuth} from "./useAuth.js";

export const useAuthenticatedFetch = () => {
    const { keycloakService } = useAuth();

    return async (url, options = {}) => {
        const authHeader = keycloakService.getAuthorizationHeader();

        if (!authHeader) {
            throw new Error('Non authentifié');
        }

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        if (response.status === 401) {
            // Token expiré, rediriger vers login
            keycloakService.logout();
            throw new Error('Session expirée');
        }

        return response;
    };
};