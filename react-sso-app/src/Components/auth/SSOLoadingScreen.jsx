import useSSO from "../../hooks/useSSO.js";
import SSOStatusIndicator from "./SSOStatusIndicator.jsx";

import { Zap } from 'lucide-react';

const SSOLoadingScreen = () => {
    const { ssoStatus } = useSSO()

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
            <div className="text-center p-8">
                <div className="mb-6">
                    <Zap className="mx-auto h-16 w-16 text-blue-600 animate-pulse" />
                </div>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Single Sign-On</h2>
                <div className="mb-6">
                    <SSOStatusIndicator />
                </div>
                <div className="w-64 bg-gray-200 rounded-full h-2">
                    <div className={`bg-blue-600 h-2 rounded-full transition-all duration-500 ${
                        ssoStatus === 'initializing' ? 'w-1/4' :
                            ssoStatus === 'checking' ? 'w-2/4' :
                                ssoStatus === 'authenticating' ? 'w-3/4' :
                                    'w-full'
                    }`}></div>
                </div>
                <p className="text-gray-600 mt-4">
                    Vérification de votre session d'authentification...
                </p>
            </div>
        </div>
    )
}

export default SSOLoadingScreen