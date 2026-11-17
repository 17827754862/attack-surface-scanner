import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Submit from "./pages/Submit";
import TaskDetail from "./pages/TaskDetail";
import Report from "./pages/Report";
import History from "./pages/History";
import AISettings from "./pages/AISettings";
import { getToken } from "./api";


function Protected({ children }) {
  const location = useLocation();
  if (!getToken()) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/scan" element={<Protected><Submit /></Protected>} />
      <Route path="/history" element={<Protected><History /></Protected>} />
      <Route path="/settings/ai" element={<Protected><AISettings /></Protected>} />
      <Route path="/tasks/:id" element={<Protected><TaskDetail /></Protected>} />
      <Route path="/tasks/:id/report" element={<Protected><Report /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
