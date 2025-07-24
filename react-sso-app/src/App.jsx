import AuthProvider from "./utils/AuthProvider.jsx";
import ProtectedRoute from "./Components/auth/ProtectedRoute.jsx";
import Dashboard from "./pages/DashboardPage.jsx";

const App = () => {
    return (
        <AuthProvider>
            <ProtectedRoute>
                <Dashboard />
            </ProtectedRoute>
        </AuthProvider>
    );
};

export default App;