import { useEffect, useState } from "react";
import { API_BASE_URL } from "@/lib/utils";
import { Dashboard } from "@/components/Dashboard";
import { Button } from "@/components/ui/button";
import { IncidentsPanel } from "@/components/IncidentsPanel";

export default function Admin() {
  const [authorized, setAuthorized] = useState<boolean | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/auth/me`, { credentials: "include" });
        if (res.ok) setAuthorized(true);
        else setAuthorized(false);
      } catch {
        setAuthorized(false);
      }
    };
    check();
  }, []);

  const logout = async () => {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("csrf_token="))?.split("=")[1];
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf || "" },
      credentials: "include",
    });
    window.location.href = "/login";
  };

  if (authorized === null) return <div className="p-6 text-sm">Checking session…</div>;
  if (!authorized) return <div className="p-6 text-sm">Not authorized. <a href="/login" className="underline">Login</a></div>;

  return (
    <div>
      <div className="flex items-center justify-end p-3 border-b border-border bg-card/50">
        <Button variant="outline" size="sm" onClick={logout}>Logout</Button>
      </div>
      <main className="p-6 space-y-6">
        <Dashboard />
        <IncidentsPanel />
      </main>
    </div>
  );
}
