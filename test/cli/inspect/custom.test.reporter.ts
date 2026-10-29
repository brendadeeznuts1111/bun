/**
 * Small Inspector Protocol reporter for TestReporter/LifecycleReporter events.
 * Invoke it with the inspector unix socket address; it emits JSON on disconnect.
 */
import type { JSC } from "../../../packages/bun-inspector-protocol/src/protocol/jsc";
import { InspectorSession, connect } from "./junit-reporter.ts";
import { SocketFramer } from "./socket-framer.ts";

export interface TestReport {
  id: number;
  name: string;
  file?: string;
  status?: JSC.TestReporter.TestStatus;
  /** Elapsed milliseconds supplied by TestReporter.end. */
  duration?: number;
  error?: JSC.LifecycleReporter.ErrorEvent;
  stdout: string[];
  stderr: string[];
}

type ReporterEvent =
  | { event: "Console.messageAdded"; params: JSC.Console.MessageAddedEvent }
  | { event: "LifecycleReporter.error"; params: JSC.LifecycleReporter.ErrorEvent };

export type ReporterDiagnostic = {
  reason: "no-active-test" | "overlapping-tests" | "unknown-test";
  activeTestIds: number[];
} & ReporterEvent;

export interface ReporterOutput {
  tests: TestReport[];
  diagnostics: ReporterDiagnostic[];
}

export class CustomTestReporter {
  readonly tests = new Map<number, TestReport>();
  readonly diagnostics: ReporterDiagnostic[] = [];
  private readonly activeTests = new Set<number>();

  constructor(private readonly session: InspectorSession) {
    session.addEventListener("TestReporter.found", params => this.found(params));
    session.addEventListener("TestReporter.start", params => this.start(params));
    session.addEventListener("TestReporter.end", params => this.end(params));
    session.addEventListener("Console.messageAdded", params => this.consoleMessage(params));
    session.addEventListener("LifecycleReporter.error", params => this.error(params));
    session.send("Inspector.enable");
    session.send("TestReporter.enable");
    session.send("LifecycleReporter.enable");
    session.send("Console.enable");
    session.send("Inspector.initialized");
  }

  private found(params: JSC.TestReporter.FoundEvent) {
    this.tests.set(params.id, {
      id: params.id,
      name: params.name ?? `Test ${params.id}`,
      file: params.url,
      stdout: [],
      stderr: [],
    });
  }

  private start(params: JSC.TestReporter.StartEvent) {
    this.activeTests.add(params.id);
  }

  private end(params: JSC.TestReporter.EndEvent) {
    this.activeTests.delete(params.id);
    const test = this.tests.get(params.id);
    if (!test) return;
    test.status = params.status;
    test.duration = params.elapsed;
  }

  private selectTest(event: ReporterEvent): TestReport | undefined {
    // Console and lifecycle events have no test ID; attribute only with one active test.
    const activeTestIds = [...this.activeTests];
    const test = activeTestIds.length === 1 ? this.tests.get(activeTestIds[0]) : undefined;
    if (test) return test;
    const reason =
      activeTestIds.length === 0 ? "no-active-test" : activeTestIds.length > 1 ? "overlapping-tests" : "unknown-test";
    this.diagnostics.push({ ...event, reason, activeTestIds });
    return undefined;
  }

  private consoleMessage(params: JSC.Console.MessageAddedEvent) {
    const test = this.selectTest({ event: "Console.messageAdded", params });
    if (!test) return;
    const { text, level } = params.message;
    if (level === "error" || level === "warning") test.stderr.push(text);
    else test.stdout.push(text);
  }

  private error(params: JSC.LifecycleReporter.ErrorEvent) {
    const test = this.selectTest({ event: "LifecycleReporter.error", params });
    if (test) test.error = params;
  }

  toJSON(): ReporterOutput {
    return { tests: [...this.tests.values()], diagnostics: this.diagnostics };
  }

  format(): string {
    return JSON.stringify(this.toJSON(), null, 2);
  }
}

if (import.meta.main) {
  const address = process.argv[2];
  if (!address) throw new Error("Usage: custom.test.reporter.ts <inspector-address>");

  const session = new InspectorSession();
  const disconnected = Promise.withResolvers<void>();
  const connection = connect(address, disconnected.resolve);
  process.send?.({ type: "inspector-listening" });
  const socket = await connection;
  session.socket = socket;
  const framer = new SocketFramer(message => session.onMessage(message));
  session.framer = framer;
  socket.data = { onData: framer.onData.bind(framer) };
  const reporter = new CustomTestReporter(session);
  await disconnected.promise;
  console.log(reporter.format());
  process.disconnect?.();
}
