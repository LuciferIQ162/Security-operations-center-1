import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: LucideIcon;
  trend?: "up" | "down" | "neutral";
  className?: string;
}

export function MetricCard({ label, value, subValue, icon: Icon, trend, className }: MetricCardProps) {
  return (
    <div
      className={cn(
        "group relative bg-card border border-border rounded-lg p-4 transition-all duration-300",
        "hover:border-primary/20 hover:glow-subtle",
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="text-2xl font-mono font-medium text-foreground">
            {value}
          </p>
          {subValue && (
            <p className={cn(
              "text-xs font-mono",
              trend === "up" && "text-success",
              trend === "down" && "text-destructive",
              trend === "neutral" && "text-muted-foreground",
              !trend && "text-muted-foreground"
            )}>
              {subValue}
            </p>
          )}
        </div>
        {Icon && (
          <div className="p-2 bg-secondary rounded-md">
            <Icon className="h-4 w-4 text-muted-foreground" />
          </div>
        )}
      </div>
      <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-primary/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}
