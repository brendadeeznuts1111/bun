import { expect, test } from "bun:test";
import { bunEnv, bunExe, tempDir } from "harness";
import { join } from "node:path";
import type { JSC } from "../../../packages/bun-inspector-protocol/src/protocol/jsc";
import { checkAndReport, checkPermissions, formatPermissionResult } from "./permission-helper.ts";
import { CustomTestReporter } from "./custom.test.reporter.ts";
import { InspectorSession } from "./junit-reporter.ts";
import { SocketFramer } from "./socket-framer.ts";

test("permission helper formats and evaluates checks", () => {
  const api = { has: (scope: string, resource?: string) => scope === "net" && resource === "example.com" };
  expect(formatPermissionResult("net", true, "example.com")).toContain("✅ net example.com");
  expect(checkAndReport("net", "example.com", api)).toBe(true);
  expect(
    checkPermissions(
      [
        { name: "net", resource: "example.com" },
        { name: "env", resource: "TOKEN" },
      ],
      api,
    ),
  ).toEqual([true, false]);
});

test("permission helper rejects an unavailable default API", () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, "permission");
  try {
    Object.defineProperty(process, "permission", { value: undefined, configurable: true });
    expect(() => checkAndReport("net")).toThrow(
      "process.permission.has is unavailable; enable the experimental permission API",
    );
  } finally {
    if (descriptor) Object.defineProperty(process, "permission", descriptor);
    else Reflect.deleteProperty(process, "permission");
  }
});

class FakeSession extends InspectorSession {
  sent: string[] = [];
  override send(method: string) {
    this.sent.push(method);
  }

  emit<Event extends keyof JSC.EventMap>(method: Event, params: JSC.EventMap[Event]) {
    this.onMessage(JSON.stringify({ method, params }));
  }
}

const lifecycleError = {
  message: "Permission denied",
  name: "Error",
  urls: ["/fixture.ts"],
  lineColumns: [4, 2],
  sourceLines: ["throw new Error('Permission denied');"],
} satisfies JSC.LifecycleReporter.ErrorEvent;

const consoleEvent = {
  message: { source: "console-api", level: "log", text: "✅ net example.com" },
} satisfies JSC.Console.MessageAddedEvent;

test("custom reporter records protocol metadata, elapsed duration, output, and lifecycle errors", () => {
  const session = new FakeSession();
  const reporter = new CustomTestReporter(session);
  session.emit("TestReporter.found", { id: 7, name: "permission check", url: "/fixture.ts", line: 4 });
  session.emit("TestReporter.start", { id: 7 });
  session.emit("Console.messageAdded", consoleEvent);
  session.emit("Console.messageAdded", { message: { source: "console-api", level: "error", text: "denied" } });
  session.emit("LifecycleReporter.error", lifecycleError);
  session.emit("TestReporter.end", { id: 7, status: "fail", elapsed: 123.456 });

  expect(reporter.toJSON()).toEqual({
    tests: [
      {
        id: 7,
        name: "permission check",
        file: "/fixture.ts",
        status: "fail",
        duration: 123.456,
        error: lifecycleError,
        stdout: ["✅ net example.com"],
        stderr: ["denied"],
      },
    ],
    diagnostics: [],
  });
  expect(session.sent).toEqual([
    "Inspector.enable",
    "TestReporter.enable",
    "LifecycleReporter.enable",
    "Console.enable",
    "Inspector.initialized",
  ]);
  expect(JSON.parse(reporter.format())).toEqual(reporter.toJSON());
});

test("custom reporter receives permission results over the Inspector socket", async () => {
  const helper = JSON.stringify(join(import.meta.dir, "permission-helper.ts"));
  using dir = tempDir("permission-reporter", {
    "permission-fixture.test.ts": `
      import { test, expect } from "bun:test";
      import { checkAndReport } from ${helper};
      test("allowed environment check", () => {
        expect(checkAndReport("env", "PERMISSION_REPORTER_ALLOWED")).toBe(true);
      });
      test("denied environment check", () => {
        expect(checkAndReport("env", "PERMISSION_REPORTER_DENIED")).toBe(false);
        console.error("permission denial diagnostic");
        throw new Error("permission fixture failure");
      });
    `,
  });
  const socketPath = join(String(dir), "inspector.sock");
  const connected = Promise.withResolvers<CustomTestReporter>();
  const disconnected = Promise.withResolvers<void>();
  const session = new InspectorSession();
  const framer = new SocketFramer(message => session.onMessage(message));
  using listener = Bun.listen<NonNullable<InspectorSession["socket"]>["data"]>({
    unix: socketPath,
    socket: {
      open(socket) {
        session.socket = socket;
        session.framer = framer;
        socket.data = { onData: framer.onData.bind(framer) };
        connected.resolve(new CustomTestReporter(session));
      },
      data(socket, data) {
        socket.data.onData(socket, data);
      },
      close() {
        disconnected.resolve();
      },
      error(_socket, error) {
        connected.reject(error);
      },
    },
  });
  await using child = Bun.spawn({
    cmd: [
      bunExe(),
      `--inspect-wait=unix:${socketPath}`,
      "--experimental-permissions",
      "--allow-inspector",
      "--allow-env=PERMISSION_REPORTER_ALLOWED",
      "test",
      "permission-fixture.test.ts",
    ],
    cwd: String(dir),
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const output = Promise.all([child.stdout.text(), child.stderr.text(), child.exited]);
  try {
    const reporter = await Promise.race([
      connected.promise,
      child.exited.then(code => {
        throw new Error(`Inspector child exited before connecting: ${code}`);
      }),
    ]);
    listener.stop();
    const [[stdout, stderr, exitCode]] = await Promise.all([output, disconnected.promise]);
    expect(stdout).toContain("PERMISSION_REPORTER_ALLOWED");
    expect(stderr).toContain("permission fixture failure");
    const report = reporter.toJSON();
    expect(report.tests).toHaveLength(2);
    const [allowed, denied] = report.tests;
    expect(allowed.name).toBe("allowed environment check");
    expect(allowed.status).toBe("pass");
    expect(allowed.stdout).toHaveLength(1);
    expect(allowed.stdout[0]).toContain("✅ env PERMISSION_REPORTER_ALLOWED");
    expect(allowed.stderr).toEqual([]);
    expect(denied.name).toBe("denied environment check");
    expect(denied.status).toBe("fail");
    expect(denied.stdout).toHaveLength(1);
    expect(denied.stdout[0]).toContain("❌ env PERMISSION_REPORTER_DENIED");
    expect(denied.stderr).toEqual(["permission denial diagnostic"]);
    expect(denied.error?.message).toBe("permission fixture failure");
    expect(denied.error?.name).toBe("Error");
    for (const result of report.tests) {
      expect(result.file).toContain("permission-fixture.test.ts");
      expect(result.duration).toBeNumber();
      expect(result.duration).toBeGreaterThanOrEqual(0);
    }
    expect(JSON.parse(reporter.format())).toEqual(report);
    expect(exitCode).toBe(1);
  } finally {
    session.socket?.end();
    child.kill();
    await output;
  }
});

test("standalone custom reporter emits JSON and exits when the Inspector disconnects", async () => {
  using dir = tempDir("permission-reporter-cli", {
    "standalone.test.ts": `
      import { test, expect } from "bun:test";
      test("standalone permission check", () => {
        expect(process.permission.has("env", "PERMISSION_REPORTER_ALLOWED")).toBe(true);
        console.log("standalone permission output");
      });
    `,
  });
  const socketPath = join(String(dir), "inspector.sock");
  const listening = Promise.withResolvers<void>();
  await using reporter = Bun.spawn({
    cmd: [bunExe(), join(import.meta.dir, "custom.test.reporter.ts"), `unix://${socketPath}`],
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
    ipc(message: unknown) {
      if (
        typeof message === "object" &&
        message !== null &&
        "type" in message &&
        message.type === "inspector-listening"
      ) {
        listening.resolve();
      }
    },
  });
  const reporterOutput = Promise.all([reporter.stdout.text(), reporter.stderr.text(), reporter.exited]);
  try {
    await Promise.race([
      listening.promise,
      reporter.exited.then(code => {
        throw new Error(`Standalone reporter exited before listening: ${code}`);
      }),
    ]);
    await using child = Bun.spawn({
      cmd: [
        bunExe(),
        `--inspect-wait=unix:${socketPath}`,
        "--experimental-permissions",
        "--allow-inspector",
        "--allow-env=PERMISSION_REPORTER_ALLOWED",
        "test",
        "standalone.test.ts",
      ],
      cwd: String(dir),
      env: bunEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([child.stdout.text(), child.stderr.text(), child.exited]);
    expect(stdout).toContain("standalone permission output");
    expect(stderr).toContain("1 pass");
    expect(exitCode).toBe(0);
    const [json, reporterStderr, reporterExitCode] = await reporterOutput;
    const report: unknown = JSON.parse(json);
    expect(report).toMatchObject({
      tests: [{ name: "standalone permission check", status: "pass", stdout: ["standalone permission output"] }],
    });
    expect(reporterStderr).toBe("");
    expect(reporterExitCode).toBe(0);
  } finally {
    reporter.kill();
    await reporterOutput;
  }
});

test.each([1, 2])("custom reporter retains ambiguous events when overlapping test %i ends first", firstEnd => {
  const session = new FakeSession();
  const reporter = new CustomTestReporter(session);
  for (const id of [1, 2]) {
    session.emit("TestReporter.found", { id, line: 1 });
    session.emit("TestReporter.start", { id });
  }
  session.emit("Console.messageAdded", consoleEvent);
  session.emit("LifecycleReporter.error", lifecycleError);
  session.emit("TestReporter.end", { id: firstEnd, status: "pass", elapsed: 2 });
  session.emit("Console.messageAdded", consoleEvent);
  const lastEnd = firstEnd === 1 ? 2 : 1;
  session.emit("TestReporter.end", { id: lastEnd, status: "pass", elapsed: 3 });
  session.emit("Console.messageAdded", consoleEvent);
  session.emit("LifecycleReporter.error", lifecycleError);

  expect(reporter.toJSON()).toEqual({
    tests: [1, 2].map(id => ({
      id,
      name: `Test ${id}`,
      file: undefined,
      status: "pass",
      duration: id === firstEnd ? 2 : 3,
      stdout: id === lastEnd ? [consoleEvent.message.text] : [],
      stderr: [],
    })),
    diagnostics: [
      { event: "Console.messageAdded", params: consoleEvent, activeTestIds: [1, 2], reason: "overlapping-tests" },
      { event: "LifecycleReporter.error", params: lifecycleError, activeTestIds: [1, 2], reason: "overlapping-tests" },
      { event: "Console.messageAdded", params: consoleEvent, activeTestIds: [], reason: "no-active-test" },
      { event: "LifecycleReporter.error", params: lifecycleError, activeTestIds: [], reason: "no-active-test" },
    ],
  });
});

test("custom reporter retains events for undiscovered test IDs", () => {
  const session = new FakeSession();
  const reporter = new CustomTestReporter(session);
  session.emit("TestReporter.start", { id: 9 });
  session.emit("Console.messageAdded", consoleEvent);
  session.emit("TestReporter.end", { id: 9, status: "skip", elapsed: 0 });
  session.emit("LifecycleReporter.error", lifecycleError);
  expect(reporter.toJSON()).toEqual({
    tests: [],
    diagnostics: [
      { event: "Console.messageAdded", params: consoleEvent, activeTestIds: [9], reason: "unknown-test" },
      { event: "LifecycleReporter.error", params: lifecycleError, activeTestIds: [], reason: "no-active-test" },
    ],
  });
});

test.each([true, false])("permission helper resets terminal color for allowed=%p", allowed => {
  const descriptor = Object.getOwnPropertyDescriptor(Bun, "color");
  if (!descriptor) throw new Error("Bun.color is unavailable");
  Object.defineProperty(Bun, "color", { ...descriptor, value: () => "\u001b[32m" });
  try {
    const output = formatPermissionResult("net", allowed, "example.com");
    expect(output.startsWith("\u001b[32m")).toBe(true);
    expect(output.endsWith("\u001b[0m")).toBe(true);
  } finally {
    Object.defineProperty(Bun, "color", descriptor);
  }
});
