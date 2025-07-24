const AccessDenied = ({ requiredRoles = [], requiredClientRoles = {} }) => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-8 text-center">
            <Shield className="h-16 w-16 text-red-500 mx-auto mb-4" />
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
export default AccessDenied;