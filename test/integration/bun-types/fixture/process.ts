import { expectType } from "./utilities";

process.memoryUsage();
process.cpuUsage().system;
process.cpuUsage().user;
process.on("SIGINT", () => {
  console.log("Interrupt from keyboard");
});

process.on("beforeExit", code => {
  expectType(code).is<number>();
  console.log("Event loop is empty and no work is left to schedule.", code);
});

process.on("exit", code => {
  expectType(code).is<number>();
  console.log("Exiting with code:", code);
});
process.kill(123, "SIGTERM");

process.getegid!();
process.geteuid!();
process.getgid!();
process.getgroups!();
process.getuid!();

process.once("SIGINT", () => {
  console.log("Interrupt from keyboard");
});

// commented methods are not yet implemented
console.log(process.allowedNodeEnvironmentFlags);
// console.log(process.channel);
// console.log(process.connected);
// console.log(process.constrainedMemory);
console.log(process.debugPort);
// console.log(process.disconnect);
// console.log(process.getActiveResourcesInfo);
// console.log(process.setActiveResourcesInfo);
// console.log(process.setuid);
// console.log(process.setgid);
// console.log(process.setegid);
// console.log(process.seteuid);
// console.log(process.setgroups);
// console.log(process.hasUncaughtExceptionCaptureCallback);
// console.log(process.initGroups);
console.log(process.listenerCount("exit"));
console.log(process.memoryUsage());
// console.log(process.report);
// console.log(process.resourceUsage);
// console.log(process.setSourceMapsEnabled());
// console.log(process.send);

for (const method of [
  "on",
  "once",
  "off",
  "addListener",
  "removeListener",
  "prependListener",
  "prependOnceListener",
] as const) {
  expectType(
    process[method]("memoryPressure", level => {
      expectType(level).is<"warning" | "critical">();
    }),
  ).is<NodeJS.Process>();
  process[method]("exit", code => {
    expectType(code).is<number>();
  });
  process[method]("warning", warning => {
    expectType(warning).is<Error>();
  });
  process[method](Symbol(), () => {});
  process[method]("customEvent", () => {});
}

expectType(process.emit("memoryPressure", "warning")).is<boolean>();
expectType(process.emit("memoryPressure", "critical")).is<boolean>();
expectType(process.emit("exit", 0)).is<boolean>();
expectType(process.emit(Symbol())).is<boolean>();
expectType(process.listeners("memoryPressure")).is<((level: "warning" | "critical") => void)[]>();

expectType(process.permission.has("fs.read")).is<boolean>();
expectType(process.permission.has("env", "PATH")).is<boolean>();
expectType(process.permission.has("net", "example.com")).is<boolean>();

process.reallyExit();
process.assert(false, "PleAsE don't Use THIs It IS dEpReCATED");
