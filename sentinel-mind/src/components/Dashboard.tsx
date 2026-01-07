import { Header } from "./Header";
import { MetricCard } from "./MetricCard";
import { AlertItem } from "./AlertItem";
import { InvestigationCard } from "./InvestigationCard";
import { ActivityFeed } from "./ActivityFeed";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  Brain,
  TrendingUp,
  Clock
} from "lucide-react";
import { useQuery, useMutation, QueryClient, useQueryClient } from "@tanstack/react-query";
import { API_BASE_URL } from "@/lib/utils";
import { Button } from "./ui/button";

function useBackendData() {
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/alerts`);
      return res.json();
    },
    refetchInterval: 5000,
  });
  const investigations = useQuery({
    queryKey: ["investigations"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/investigations`);
      return res.json();
    },
    refetchInterval: 7000,
  });
  const activity = useQuery({
    queryKey: ["activity"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/activity`);
      return res.json();
    },
    refetchInterval: 4000,
  });
  const stats = useQuery({
    queryKey: ["stats"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/stats`);
      return res.json();
    },
    refetchInterval: 10000,
  });
  return { alerts, investigations, activity, stats };
}

function GenerateExampleButton() {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      await fetch(`${API_BASE_URL}/alerts/example`, { method: "POST" });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["investigations"] });
      qc.invalidateQueries({ queryKey: ["activity"] });
    },
  });
  return (
    <Button size="sm" variant="outline" onClick={() => mutation.mutate()}>
      Generate Example Alert
    </Button>
  );
}

export function Dashboard() {
  const { alerts, investigations, activity, stats } = useBackendData();
  const alertItems = alerts.data?.items ?? [];
  const investigationItems = investigations.data?.items ?? [];
  const activityItems = activity.data?.items ?? [];
  const metrics = stats.data ?? {};
  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="p-6 space-y-6">
        {/* Metrics Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <MetricCard
            label="Active Alerts"
            value={alertItems.length}
            subValue=""
            trend="up"
            icon={AlertTriangle}
          />
          <MetricCard
            label="Investigating"
            value={alertItems.filter((a: any) => a.status === "investigating").length}
            icon={Brain}
          />
          <MetricCard
            label="Resolved Today"
            value={investigationItems.length}
            subValue=""
            trend="neutral"
            icon={CheckCircle2}
          />
          <MetricCard
            label="Avg Resolution"
            value="—"
            subValue=""
            trend="down"
            icon={Clock}
          />
          <MetricCard
            label="False Positives"
            value={(metrics.learning_metrics?.false_positives ?? 0).toString()}
            subValue=""
            trend="down"
            icon={TrendingUp}
          />
          <MetricCard
            label="True Positives"
            value={(metrics.learning_metrics?.true_positives ?? 0).toString()}
            subValue=""
            icon={Shield}
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Alert Queue */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-medium text-foreground">Alert Queue</h2>
                <p className="text-xs text-muted-foreground font-mono">
                  Prioritized by severity and context
                </p>
              </div>
              <div className="flex items-center gap-2">
                <GenerateExampleButton />
              </div>
            </div>
            <div className="space-y-2">
              {alertItems.map((alert: any) => (
                <AlertItem key={alert.id} {...alert} />
              ))}
            </div>
          </div>

          {/* Activity Feed */}
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-medium text-foreground">Agent Activity</h2>
              <p className="text-xs text-muted-foreground font-mono">
                Real-time operations log
              </p>
            </div>
            <div className="bg-card border border-border rounded-lg p-3 max-h-[400px] overflow-y-auto scrollbar-thin">
              <ActivityFeed activities={activityItems} />
            </div>
          </div>
        </div>

        {/* Active Investigations */}
        <div className="space-y-4">
          <div>
            <h2 className="text-sm font-medium text-foreground">Active Investigations</h2>
            <p className="text-xs text-muted-foreground font-mono">
              Autonomous investigation pipelines currently running
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {investigationItems.map((inv: any) => (
              <InvestigationCard key={inv.alertId} {...inv} />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
