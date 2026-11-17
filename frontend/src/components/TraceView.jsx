export default function TraceView({ events }) {
  return (
    <div className="console">
      {events.length === 0 ? (
        <div className="px-4 py-8 text-center text-[#517096]">等待执行事件...</div>
      ) : (
        events.map((event, index) => (
          <div key={`${event.node || event.node_name || "event"}-${index}`} className="console-row">
            <span className="console-index">{String(index + 1).padStart(2, "0")}</span>
            <span className="console-node truncate">{event.node || event.node_name || "-"}</span>
            <span className="console-message">
              <span className="mr-2 text-[#577aa5]">{event.event || event.status || ""}</span>
              {event.summary || event.error || ""}
            </span>
          </div>
        ))
      )}
    </div>
  );
}
