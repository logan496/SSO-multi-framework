import useSSO from "../hooks/useSSO.js";

const HomePage = () => {
  const { user, hasRole, keycloak } = useSSO();

  return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Bienvenue dans l'écosystème SSO ! 🚀
          </h1>
          <p className="text-gray-600">
            Vous êtes connecté automatiquement grâce au Single Sign-On.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="bg-white p-6 rounded-lg shadow">
            <Globe className="h-8 w-8 text-blue-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Single Sign-On</h3>
            <p className="text-gray-600 text-sm">
              Une seule authentification pour toutes vos applications d'entreprise.
            </p>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <CheckCircle className="h-8 w-8 text-green-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Session Active</h3>
            <p className="text-gray-600 text-sm">
              Votre session est automatiquement synchronisée avec les autres apps.
            </p>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <Shield className="h-8 w-8 text-purple-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Sécurité Renforcée</h3>
            <p className="text-gray-600 text-sm">
              Authentification centralisée avec rafraîchissement automatique des tokens.
            </p>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <User className="h-8 w-8 text-indigo-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Profil Utilisateur</h3>
            <div className="text-sm text-gray-600 space-y-1">
              <p><strong>Nom:</strong> {user?.name}</p>
              <p><strong>Email:</strong> {user?.email}</p>
              <p><strong>Username:</strong> {user?.preferred_username}</p>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <Lock className="h-8 w-8 text-orange-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Rôles & Permissions</h3>
            <div className="flex flex-wrap gap-2">
              {user?.realm_access?.roles?.map(role => (
                  <span key={role} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                {role}
              </span>
              ))}
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <RefreshCw className="h-8 w-8 text-teal-500 mb-4" />
            <h3 className="text-lg font-semibold mb-2">Token Management</h3>
            <p className="text-gray-600 text-sm">
              Les tokens sont automatiquement rafraîchis en arrière-plan.
            </p>
            <div className="mt-2 text-xs text-gray-500">
              Expires: {keycloak?.isTokenExpired() ? 'Expiré' : 'Valide'}
            </div>
          </div>
        </div>

        {hasRole('admin') && (
            <div className="mt-8 bg-gradient-to-r from-red-50 to-pink-50 p-6 rounded-lg border border-red-200">
              <h3 className="text-lg font-semibold text-red-800 mb-2">
                🛡️ Zone d'Administration SSO
              </h3>
              <p className="text-red-600 mb-4">
                En tant qu'administrateur, vous avez accès à la gestion SSO centralisée.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-white p-4 rounded border">
                  <h4 className="font-medium text-gray-900">Applications Connectées</h4>
                  <ul className="text-sm text-gray-600 mt-2">
                    <li>• App React (actuelle)</li>
                    <li>• App Vue.js</li>
                    <li>• App Angular</li>
                    <li>• API Backend</li>
                  </ul>
                </div>
                <div className="bg-white p-4 rounded border">
                  <h4 className="font-medium text-gray-900">Sessions Actives</h4>
                  <p className="text-sm text-gray-600 mt-2">
                    Surveillance en temps réel des sessions utilisateur.
                  </p>
                </div>
              </div>
            </div>
        )}
      </div>
  );
};

export default HomePage
