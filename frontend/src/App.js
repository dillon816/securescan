import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Upload from "./pages/Upload";
import Scan from "./pages/Scan";
import Dashboard from "./pages/Dashboard";
import Fixes from "./pages/Fixes";
import SidebarLayout from "./components/SidebarLayout";

// Configuration des routes principales de l'application
function App() {
  return (
    <Router>
      <SidebarLayout>
        <Routes>
          <Route path="/" element={<Upload />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/fixes" element={<Fixes />} />
        </Routes>
      </SidebarLayout>
    </Router>
  );
}
export default App;