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

/** Extract valid standard error fields without assuming a caught value is an Error. */
export function normalizePermissionError(value: unknown): Bun.ErrorLike {
  const error: Bun.ErrorLike = {
    name: "Error",
    message: typeof value === "string" ? value : "Non-error value thrown",
  };
  if (typeof value !== "object" || value === null) return error;

  try {
    const name = "name" in value ? value.name : undefined;
    const message = "message" in value ? value.message : undefined;
    const stack = "stack" in value ? value.stack : undefined;
    const code = "code" in value ? value.code : undefined;
    const errno = "errno" in value ? value.errno : undefined;
    const syscall = "syscall" in value ? value.syscall : undefined;
    if (typeof name === "string") error.name = name;
    if (typeof message === "string") error.message = message;
    if (typeof stack === "string") error.stack = stack;
    if (typeof code === "string") error.code = code;
    if (typeof errno === "number") error.errno = errno;
    if (typeof syscall === "string") error.syscall = syscall;
    if ("cause" in value) error.cause = value.cause;
    return error;
  } catch {
    // Accessors and proxies can throw even when the property exists.
    return { name: "Error", message: "Unable to read thrown error details" };
  }
}
