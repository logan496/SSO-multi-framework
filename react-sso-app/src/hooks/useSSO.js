import { useContext } from "react";
import SSOContext from "../context/SSOContext.js";

const useSSO = () => {
    const context = useContext(SSOContext);
    if (!context) {
        throw new Error('useSSO must be used within SSOProvider');
    }
    return context;
};

export default useSSO;