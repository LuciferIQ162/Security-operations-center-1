import { cn } from "@/lib/utils";
import { StatusIndicator } from "./StatusIndicator";
import { Brain, Clock, CheckCircle2, AlertCircle } from "lucide-react";

type Stage = "classification" | "investigation" | "decision" | "conclusion";

interface InvestigationCardProps {
  alertId: string;
  title: string;
  currentStage: Stage;
  riskScore?: number;
  duration: string;
  findings?: number;
}

const stages: Stage[] = ["classification", "investigation", "decision", "conclusion"];

const stageLabels: Record<Stage, string> = {
  classification: "Classify",
  investigation: "Investigate",
  decision: "Decide",
  conclusion: "Conclude",
};

export function InvestigationCard({
  alertId,
  title,
  currentStage,
  riskScore,
  duration,
  findings = 0,
}: InvestigationCardProps) {
  const currentIndex = stages.indexOf(currentStage);

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-4 hover:border-primary/20 transition-colors">
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-primary">{alertId}</span>
            <StatusIndicator status="processing" size="sm" pulse />
          </div>
          <p className="text-sm font-medium text-foreground line-clamp-1">{title}</p>
        </div>
        <div className="p-2 bg-primary/10 rounded-md">
          <Brain className="h-4 w-4 text-primary" />
        </div>
      </div>

      {/* Stage Progress */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          {stages.map((stage, index) => (
            <div key={stage} className="flex items-center">
              <div
                className={cn(
                  "flex items-center justify-center w-6 h-6 rounded-full text-xs font-mono",
                  index < currentIndex && "bg-primary text-primary-foreground",
                  index === currentIndex && "bg-primary/20 text-primary border border-primary",
                  index > currentIndex && "bg-secondary text-muted-foreground"
                )}
              >
                {index < currentIndex ? (
                  <CheckCircle2 className="h-3 w-3" />
                ) : (
                  index + 1
                )}
              </div>
              {index < stages.length - 1 && (
                <div
                  className={cn(
                    "w-8 h-px mx-1",
                    index < currentIndex ? "bg-primary" : "bg-border"
                  )}
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          {stages.map((stage) => (
            <span key={stage} className="w-12 text-center">
              {stageLabels[stage]}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="flex items-center justify-between pt-2 border-t border-border">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground">
            <Clock className="h-3 w-3" />
            <span>{duration}</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground">
            <AlertCircle className="h-3 w-3" />
            <span>{findings} findings</span>
          </div>
        </div>
        {riskScore !== undefined && (
          <div
            className={cn(
              "px-2 py-0.5 rounded text-xs font-mono font-medium",
              riskScore >= 7 && "bg-destructive/10 text-destructive",
              riskScore >= 4 && riskScore < 7 && "bg-warning/10 text-warning",
              riskScore < 4 && "bg-success/10 text-success"
            )}
          >
            Risk: {riskScore}/10
          </div>
        )}
      </div>
    </div>
  );
}
