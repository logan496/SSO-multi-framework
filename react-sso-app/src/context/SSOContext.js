import { createContext } from "react";

const SSOContext = createContext({
    keycloak: null,
    authenticated: false,
    loading: true,
    user: null,
    ssoStatus: 'initializing',
    login: () => {},
    logout: () => {},
    hasRole: () => false,
    hasRealmRole: () => false
});

export default SSOContext;