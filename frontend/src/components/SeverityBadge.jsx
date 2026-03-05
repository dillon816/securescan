// Affiche un badge coloré selon la sévérité
export default function SeverityBadge({ severity }) {
  const styles = {
    Critical: {
      bg: "rgba(255, 99, 132, 0.18)",
      border: "rgba(255, 99, 132, 0.6)",
      text: "#b00020",
    },
    High: {
      bg: "rgba(255, 159, 64, 0.18)",
      border: "rgba(255, 159, 64, 0.6)",
      text: "#a04e00",
    },
    Medium: {
      bg: "rgba(54, 162, 235, 0.18)",
      border: "rgba(54, 162, 235, 0.6)",
      text: "#1f5fa8",
    },
    Low: {
      bg: "rgba(75, 192, 192, 0.18)",
      border: "rgba(75, 192, 192, 0.6)",
      text: "#1c7a7a",
    },
    Info: {
      bg: "rgba(200,200,200,0.18)",
      border: "rgba(180,180,180,0.6)",
      text: "#555",
    },
  };

  const s = styles[severity] ?? styles.Info;

  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 12px",
        borderRadius: 999,
        backgroundColor: s.bg,
        border: `1px solid ${s.border}`,
        color: s.text,
        fontSize: 13,
        fontWeight: 700,
        whiteSpace: "nowrap",
      }}
    >
      {severity}
    </span>
  );
}
