import {AlertCircle} from "lucide-react";

const ErrorDisplay = ({ error, onRetry }) => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8 text-center">
            <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Erreur d'authentification</h2>
            <p className="text-gray-600 mb-6">{error}</p>
            <button
                onClick={onRetry}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
                Réessayer
            </button>
        </div>
    </div>
);

export default ErrorDisplay;