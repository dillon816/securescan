import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import "../index.css";

// Layout avec sidebar pour la navigation
export default function SidebarLayout({ children }) {
  const location = useLocation();
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  useEffect(() => {
    setIsMobileOpen(false);
  }, [location.pathname]);
  const isActive = (path) => location.pathname === path;

  const linkStyle = (active) => ({
    display: "block",
    padding: "12px 20px",
    margin: "8px 0",
    borderRadius: "12px",
    textDecoration: "none",
    color: active ? "#b54a72" : "#555",
    backgroundColor: active ? "rgba(255, 182, 193, 0.15)" : "transparent",
    fontWeight: active ? "800" : "600",
    transition: "all 0.2s ease-in-out",
  });

  return (
    <div className="app-container">
      {/* HEADER MOBILE */}
      <div className="mobile-header">
        <h2 className="mobile-logo">
          🛡️ Secure<span>Scan</span>
        </h2>
        <button
          className="menu-toggle-btn"
          onClick={() => setIsMobileOpen(!isMobileOpen)}
          aria-label="Ouvrir le menu"
        >
          {isMobileOpen ? "✕" : "☰"}
        </button>
      </div>

      {/* OVERLAY */}
      <div
        className={`mobile-overlay ${isMobileOpen ? "open" : ""}`}
        onClick={() => setIsMobileOpen(false)}
      ></div>

      {/* SIDEBAR */}
      <div className={`sidebar ${isMobileOpen ? "open" : ""}`}>
        <div style={{ padding: "0 10px", marginBottom: "40px", marginTop: "10px" }}>
          <h2 style={{ margin: 0, color: "#2d3748", fontSize: "24px", fontWeight: "900" }}>
            🛡️ Secure<span style={{ color: "#b54a72" }}>Scan</span>
          </h2>
          <p style={{ margin: 0, fontSize: "12px", color: "#a0aec0", marginTop: "4px" }}>
            Codez en paix.
          </p>
        </div>

        {/* Liens de navigation */}
        <nav style={{ flex: 1 }}>
          <Link to="/" style={linkStyle(isActive("/"))}>
            🚀 Lancer un Scan
          </Link>
          <Link to="/dashboard" style={linkStyle(isActive("/dashboard") || isActive("/scan"))}>
            📊 Dashboard
          </Link>
          <Link to="/fixes" style={linkStyle(isActive("/fixes"))}>
            ✨ Auto-Fix & Rapport
          </Link>
        </nav>

        {/* Pied de page du Sidebar */}
        <div
          style={{
            padding: "10px",
            fontSize: "12px",
            color: "#a0aec0",
            borderTop: "1px solid #edf2f7",
            paddingTop: "20px",
          }}
        >
          <b>Hackathon 2026</b>
          <br />
          Équipe 18
        </div>
      </div>

      {/* CONTENU PRINCIPAL */}
      <div className="main-content">{children}</div>
    </div>
  );
}
