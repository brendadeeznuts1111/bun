/** A permission check suitable for use from Bun tests and fixtures. */
export interface PermissionAPI {
  has(scope: string, resource?: string): boolean;
}

export interface PermissionCheck {
  name: string;
  resource?: string;
}

export function formatPermissionResult(scope: string, allowed: boolean, resource?: string): string {
  const label = `${scope}${resource ? ` ${resource}` : ""}`;
  const icon = allowed ? "✅" : "❌";

  // Bun.color is not available in every test host, so keep formatting optional.
  const color = typeof Bun !== "undefined" && typeof Bun.color === "function";
  if (!color) return `${icon} ${label}`;

  const ansi = Bun.color(allowed ? "green" : "red", "ansi") || "";
  const reset = ansi ? "\u001b[0m" : "";
  return `${ansi}${icon} ${label}${reset}`;
}

export function checkAndReport(scope: string, resource?: string, api?: PermissionAPI): boolean {
  const permission = api ?? globalThis.process.permission;
  if (!permission || typeof permission.has !== "function") {
    throw new Error("process.permission.has is unavailable; enable the experimental permission API");
  }

  const allowed = Boolean(permission.has(scope, resource));
  console.log(formatPermissionResult(scope, allowed, resource));
  return allowed;
}

export function checkPermissions(checks: PermissionCheck[], api?: PermissionAPI): boolean[] {
  return checks.map(({ name, resource }) => checkAndReport(name, resource, api));
}
