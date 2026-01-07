import { useState } from "react";
import { API_BASE_URL } from "@/lib/utils";
import { Button } from "@/components/ui/button";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await fetch(`${API_BASE_URL}/auth/csrf`, { credentials: "include" });
      const csrf = document.cookie.split("; ").find((c) => c.startsWith("csrf_token="))?.split("=")[1];
      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf || "",
        },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        throw new Error("Invalid credentials");
      }
      window.location.href = "/admin";
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <form onSubmit={onSubmit} className="w-full max-w-sm bg-card border border-border rounded-lg p-4 space-y-3">
        <h1 className="text-sm font-semibold text-foreground">Admin Login</h1>
        <div className="space-y-2">
          <label className="text-xs font-mono text-muted-foreground">Username</label>
          <input
            className="w-full px-2 py-1 border border-border rounded bg-background text-foreground text-sm"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="space-y-2">
          <label className="text-xs font-mono text-muted-foreground">Password</label>
          <input
            type="password"
            className="w-full px-2 py-1 border border-border rounded bg-background text-foreground text-sm"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        {error && <div className="text-destructive text-xs font-mono">{error}</div>}
        <Button type="submit" disabled={loading} className="w-full">
          {loading ? "Signing in..." : "Sign In"}
        </Button>
      </form>
    </div>
  );
}
