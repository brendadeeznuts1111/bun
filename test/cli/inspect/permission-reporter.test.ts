import { expect, test } from "bun:test";
import type { JSC } from "../../../packages/bun-inspector-protocol/src/protocol/jsc";
import { checkAndReport, checkPermissions, formatPermissionResult } from "./permission-helper.ts";
import { CustomTestReporter } from "./custom.test.reporter.ts";
import { InspectorSession } from "./junit-reporter.ts";

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
  ]);
  expect(JSON.parse(reporter.format())).toEqual(reporter.toJSON());
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
