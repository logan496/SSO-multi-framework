import {Loader} from "lucide-react";

const LoadingScreen = () => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
            <Loader className="h-12 w-12 text-blue-600 mx-auto mb-4 animate-spin" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Initialisation...</h2>
            <p className="text-gray-600">Connexion au serveur d'authentification</p>
        </div>
    </div>
);

export default LoadingScreen;