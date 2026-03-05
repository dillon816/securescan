// Affiche un badge avec le code OWASP
export default function OwaspBadge({ code }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 12px",
        borderRadius: 999,
        backgroundColor: "rgba(0,0,0,0.05)",
        border: "1px solid #ddd",
        fontSize: 13,
        fontWeight: 700,
        color: "#444",
        whiteSpace: "nowrap",
      }}
    >
      {code}
    </span>
  );
}
