import useSSO from "../../hooks/useSSO.js";
import {AlertCircle, CheckCircle, Globe, LogOut, RefreshCw} from "lucide-react";

const SSOStatusIndicator = () => {
    const { ssoStatus, authenticated, user } = useSSO();

    const getStatusInfo = () => {
        switch (ssoStatus) {
            case 'initializing':
                return { color: 'bg-gray-500', text: 'Initialisation...', icon: RefreshCw };
            case 'checking':
                return { color: 'bg-blue-500', text: 'Vérification SSO...', icon: Globe };
            case 'authenticating':
                return { color: 'bg-yellow-500', text: 'Authentification...', icon: Lock };
            case 'authenticated':
                return { color: 'bg-green-500', text: 'Connecté SSO', icon: CheckCircle };
            case 'unauthenticated':
                return { color: 'bg-red-500', text: 'Non connecté', icon: AlertCircle };
            case 'logging-out':
                return { color: 'bg-orange-500', text: 'Déconnexion...', icon: LogOut };
            case 'error':
                return { color: 'bg-red-600', text: 'Erreur SSO', icon: AlertCircle };
            default:
                return { color: 'bg-gray-500', text: 'Inconnu', icon: AlertCircle };
        }
    };

    const { color, text, icon: Icon } = getStatusInfo();

    return (
        <div className="flex items-center space-x-2 text-sm">
            <div className={`w-3 h-3 rounded-full ${color} ${ssoStatus === 'checking' || ssoStatus === 'initializing' ? 'animate-pulse' : ''}`}></div>
            <Icon className="h-4 w-4 text-gray-600" />
            <span className="text-gray-700">{text}</span>
            {authenticated && user && (
                <span className="text-xs text-gray-500">({user.preferred_username})</span>
            )}
        </div>
    );
};

export default SSOStatusIndicator;