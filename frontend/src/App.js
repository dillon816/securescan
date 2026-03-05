import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Upload from "./pages/Upload";
import Scan from "./pages/Scan";
import Dashboard from "./pages/Dashboard";
import Fixes from "./pages/Fixes";

// Configure les routes de l'application
function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Upload />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/fixes" element={<Fixes />} />
      </Routes>
    </Router>
  );
}
export default App;