import { StatusIndicator } from "./StatusIndicator";
import { Shield, Bell, Settings } from "lucide-react";
import { toast } from "sonner";
import { API_BASE_URL } from "@/lib/utils";

export function Header() {
  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-border bg-card/50 backdrop-blur-sm">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-primary/10 rounded-md">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight text-foreground">
              SOC Agent
            </h1>
            <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              Autonomous Security Operations
            </p>
          </div>
        </div>
        <div className="h-6 w-px bg-border" />
        <StatusIndicator status="active" label="System Online" pulse />
      </div>

      <div className="flex items-center gap-2">
        <button
          className="relative p-2 rounded-md hover:bg-secondary transition-colors"
          onClick={async () => {
            try {
              const res = await fetch(`${API_BASE_URL}/activity`, { credentials: "include" });
              if (!res.ok) {
                toast.error("Unable to fetch notifications");
                return;
              }
              const data = await res.json();
              const items = data?.items?.slice(0, 3) ?? [];
              if (items.length === 0) {
                toast("No new activity");
                return;
              }
              items.forEach((i: any) => toast(`${i.type}: ${i.message}`));
            } catch {
              toast.error("Notification error");
            }
          }}
        >
          <Bell className="h-4 w-4 text-muted-foreground" />
          <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 bg-primary rounded-full" />
        </button>
        <button className="p-2 rounded-md hover:bg-secondary transition-colors">
          <Settings className="h-4 w-4 text-muted-foreground" />
        </button>
        <div className="ml-2 h-6 w-px bg-border" />
        <div className="flex items-center gap-2 px-2">
          <div className="h-7 w-7 rounded-md bg-secondary flex items-center justify-center">
            <span className="text-xs font-mono font-medium text-muted-foreground">SA</span>
          </div>
        </div>
      </div>
    </header>
  );
}
