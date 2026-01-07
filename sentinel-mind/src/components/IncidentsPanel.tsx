import { useQuery } from "@tanstack/react-query";
import { API_BASE_URL, cn } from "@/lib/utils";

export function IncidentsPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/incidents`, { credentials: "include" });
      if (!res.ok) throw new Error("Not authorized or server error");
      return res.json();
    },
    refetchInterval: 8000,
  });

  const incidents = data?.incidents ?? [];
  const actions = data?.actions ?? [];
  const accessLogs = data?.access_logs ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-medium text-foreground">Incidents</h2>
        <p className="text-xs text-muted-foreground font-mono">
          Executed response actions and security audit trail
        </p>
      </div>
      {isLoading && <div className="text-xs">Loading incidents…</div>}
      {error && <div className="text-xs text-destructive">Failed to load incidents</div>}
      {!isLoading && !error && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-card border border-border rounded-lg p-3">
            <h3 className="text-xs font-mono uppercase text-muted-foreground mb-2">Recent Incidents</h3>
            <div className="space-y-2">
              {incidents.map((i: any) => (
                <div key={i.id} className="p-2 rounded border border-border hover:bg-secondary/50">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-primary">{i.id.slice(0, 8)}</span>
                    <span className="text-xs font-mono">{i.created_at}</span>
                  </div>
                  <p className="text-sm font-medium text-foreground truncate">{i.title}</p>
                  <div className="text-[10px] font-mono text-muted-foreground">
                    Severity: {i.severity} • Findings: {i.findings}
                  </div>
                </div>
              ))}
              {incidents.length === 0 && (
                <div className="text-xs text-muted-foreground">No incidents yet</div>
              )}
            </div>
          </div>
          <div className="bg-card border border-border rounded-lg p-3">
            <h3 className="text-xs font-mono uppercase text-muted-foreground mb-2">Response Actions</h3>
            <div className="space-y-2">
              {actions.map((a: any, idx: number) => (
                <div key={`${a.alert_id}-${idx}`} className="p-2 rounded border border-border hover:bg-secondary/50">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase">{a.action_type}</span>
                    <span className={cn("text-[10px] font-mono", a.status === "executed" ? "text-success" : "text-muted-foreground")}>
                      {a.status}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-muted-foreground">
                    Target: {a.target || "—"} • {a.timestamp}
                  </div>
                  <p className="text-xs">{a.details}</p>
                </div>
              ))}
              {actions.length === 0 && (
                <div className="text-xs text-muted-foreground">No actions recorded</div>
              )}
            </div>
          </div>
          <div className="bg-card border border-border rounded-lg p-3">
            <h3 className="text-xs font-mono uppercase text-muted-foreground mb-2">Access Logs</h3>
            <div className="space-y-2">
              {accessLogs.map((l: any, idx: number) => (
                <div key={idx} className="p-2 rounded border border-border hover:bg-secondary/50">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono">{l.username}</span>
                    <span className="text-[10px] font-mono">{l.timestamp}</span>
                  </div>
                  <div className="text-[10px] font-mono text-muted-foreground">
                    IP: {l.ip_address || "—"} • {l.success ? "Success" : `Fail: ${l.reason || "unknown"}`}
                  </div>
                </div>
              ))}
              {accessLogs.length === 0 && (
                <div className="text-xs text-muted-foreground">No access logs</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
