import { cn } from "@/lib/utils";
import { Check, AlertTriangle, Search, Brain, FileText } from "lucide-react";

type ActivityType = "alert_ingested" | "investigation_started" | "finding_discovered" | "decision_made" | "conclusion_generated";

interface Activity {
  id: string;
  type: ActivityType;
  message: string;
  timestamp: string;
}

interface ActivityFeedProps {
  activities: Activity[];
}

const activityConfig: Record<ActivityType, { icon: typeof Check; color: string }> = {
  alert_ingested: { icon: AlertTriangle, color: "text-warning" },
  investigation_started: { icon: Search, color: "text-info" },
  finding_discovered: { icon: FileText, color: "text-accent-foreground" },
  decision_made: { icon: Brain, color: "text-primary" },
  conclusion_generated: { icon: Check, color: "text-success" },
};

export function ActivityFeed({ activities }: ActivityFeedProps) {
  return (
    <div className="space-y-1">
      {activities.map((activity, index) => {
        const config = activityConfig[activity.type];
        const Icon = config.icon;

        return (
          <div
            key={activity.id}
            className={cn(
              "flex items-start gap-3 p-2 rounded-md transition-colors hover:bg-secondary/50",
              "animate-fade-in"
            )}
            style={{ animationDelay: `${index * 50}ms` }}
          >
            <div className={cn("mt-0.5", config.color)}>
              <Icon className="h-3.5 w-3.5" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-foreground leading-relaxed">
                {activity.message}
              </p>
            </div>
            <span className="flex-shrink-0 text-[10px] font-mono text-muted-foreground">
              {activity.timestamp}
            </span>
          </div>
        );
      })}
    </div>
  );
}
