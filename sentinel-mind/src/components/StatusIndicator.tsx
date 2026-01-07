import { cn } from "@/lib/utils";

type Status = "active" | "idle" | "processing" | "error" | "warning";

interface StatusIndicatorProps {
  status: Status;
  size?: "sm" | "md" | "lg";
  pulse?: boolean;
  label?: string;
}

const statusStyles: Record<Status, string> = {
  active: "bg-success",
  idle: "bg-muted-foreground",
  processing: "bg-primary",
  error: "bg-destructive",
  warning: "bg-warning",
};

const sizeStyles = {
  sm: "h-1.5 w-1.5",
  md: "h-2 w-2",
  lg: "h-2.5 w-2.5",
};

export function StatusIndicator({ status, size = "md", pulse = false, label }: StatusIndicatorProps) {
  return (
    <div className="flex items-center gap-2">
      <div className="relative flex items-center justify-center">
        <span
          className={cn(
            "rounded-full",
            statusStyles[status],
            sizeStyles[size],
            pulse && "animate-pulse-subtle"
          )}
        />
        {pulse && (
          <span
            className={cn(
              "absolute rounded-full opacity-40",
              statusStyles[status],
              size === "sm" ? "h-3 w-3" : size === "md" ? "h-4 w-4" : "h-5 w-5",
              "animate-ping"
            )}
          />
        )}
      </div>
      {label && (
        <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
          {label}
        </span>
      )}
    </div>
  );
}
