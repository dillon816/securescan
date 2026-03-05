// Affiche du code formaté dans une boîte
export default function CodeBox({ text }) {
  return (
    <pre
      style={{
        margin: 0,
        padding: 14,
        borderRadius: 14,
        backgroundColor: "#fafafa",
        border: "1px solid #eee",
        overflowX: "auto",
        fontSize: 13,
        lineHeight: 1.4,
        whiteSpace: "pre-wrap",
      }}
    >
      {text}
    </pre>
  );
}
