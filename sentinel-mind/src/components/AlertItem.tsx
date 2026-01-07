import { cn } from "@/lib/utils";
import { StatusIndicator } from "./StatusIndicator";
import { AlertTriangle, Shield, Cloud, Mail, Server } from "lucide-react";

type Severity = "critical" | "high" | "medium" | "low";
type AlertType = "edr" | "phishing" | "cloud" | "network" | "identity" | "unknown";
type AlertStatus = "investigating" | "resolved" | "escalated" | "pending";

interface AlertItemProps {
  id: string;
  title: string;
  type: AlertType;
  severity: Severity;
  status: AlertStatus;
  timestamp: string;
  hostname?: string;
}

const severityStyles: Record<Severity, string> = {
  critical: "text-destructive border-destructive/30 bg-destructive/5",
  high: "text-warning border-warning/30 bg-warning/5",
  medium: "text-info border-info/30 bg-info/5",
  low: "text-muted-foreground border-border bg-secondary/50",
};

const typeIcons: Record<AlertType, typeof AlertTriangle> = {
  edr: Shield,
  phishing: Mail,
  cloud: Cloud,
  network: Server,
  identity: Shield,
  unknown: AlertTriangle,
};

const statusMap: Record<AlertStatus, "active" | "processing" | "idle" | "warning"> = {
  investigating: "processing",
  resolved: "idle",
  escalated: "warning",
  pending: "active",
};

export function AlertItem({ id, title, type, severity, status, timestamp, hostname }: AlertItemProps) {
  const Icon = typeIcons[type] ?? AlertTriangle;

  return (
    <div
      className={cn(
        "group relative flex items-center gap-4 p-3 rounded-md border transition-all duration-200 cursor-pointer",
        "hover:bg-secondary/50",
        severityStyles[severity]
      )}
    >
      <div className="flex-shrink-0">
        <div className="p-2 bg-secondary/80 rounded-md">
          <Icon className="h-4 w-4" />
        </div>
      </div>

      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-muted-foreground uppercase">
            {id}
          </span>
          <StatusIndicator status={statusMap[status]} size="sm" pulse={status === "investigating"} />
        </div>
        <p className="text-sm font-medium text-foreground truncate">
          {title}
        </p>
        <div className="flex items-center gap-3 text-xs font-mono text-muted-foreground">
          <span className="uppercase">{type}</span>
          {hostname && (
            <>
              <span className="text-border">•</span>
              <span>{hostname}</span>
            </>
          )}
        </div>
      </div>

      <div className="flex-shrink-0 text-right">
        <span className="text-xs font-mono text-muted-foreground">
          {timestamp}
        </span>
      </div>

      <div className="absolute inset-y-0 left-0 w-0.5 bg-current opacity-60 rounded-l-md" />
    </div>
  );
}
