import { expect, test } from "bun:test";
import { bunEnv, bunExe, tempDir } from "harness";
import { join } from "node:path";

async function run(args: string[], env = bunEnv) {
  await using proc = Bun.spawn({
    cmd: [bunExe(), "--no-env-file", ...args],
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
  return { stdout, stderr, exitCode };
}

test("permission flags require the experimental gate", async () => {
  const result = await run(["--secure", "--allow-net=api.example.com", "-e", "console.log('ran')"]);
  expect(result.stdout).toBe("");
  expect(result.stderr).toContain("Permission flags require --experimental-permissions");
  expect(result.exitCode).toBe(1);
});

test("default mode remains unrestricted for the additive query API", async () => {
  const result = await run([
    "-e",
    "console.log(JSON.stringify([process.permission.has('net', 'api.example.com'), process.permission.has('fs.read', '/private/file')]))",
  ]);
  expect(result.stdout).toBe("[true,true]\n");
  expect(result.exitCode).toBe(0);
});

test("filesystem permission flags warn while Node fs paths are gated", async () => {
  const result = await run(["--experimental-permissions", "--secure", "--allow-read=/tmp", "-e", "console.log('ran')"]);
  expect(result.stdout).toBe("ran\n");
  expect(result.stderr).toContain("filesystem permissions are experimental and partial");
  expect(result.exitCode).toBe(0);
});

test("experimental filesystem permissions allow only listed reads", async () => {
  using directory = tempDir("permission-paths", {
    "allowed.txt": "allowed",
    "denied.txt": "denied",
  });
  const allowedPath = join(String(directory), "allowed.txt");
  const deniedPath = join(String(directory), "denied.txt");
  const allowed = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${allowedPath}`,
    "-e",
    `console.log(require('fs').readFileSync(${JSON.stringify(allowedPath)}, 'utf8'))`,
  ]);
  expect(allowed.stdout).toBe("allowed\n");
  expect(allowed.exitCode).toBe(0);

  const denied = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${allowedPath}`,
    "-e",
    `require('fs').readFileSync(${JSON.stringify(deniedPath)}, 'utf8')`,
  ]);
  expect(denied.exitCode).not.toBe(0);
  expect(`${denied.stdout}${denied.stderr}`).toMatch(/EACCES|Permission denied|AccessDenied/);
});

test("process.permission.has reports experimental network grants", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-net=api.example.com",
    "-e",
    "console.log(JSON.stringify([process.permission.has('net', 'api.example.com'), process.permission.has('net', 'other.example.com')]))",
  ]);
  expect(result.stdout).toBe("[true,false]\n");
  expect(result.exitCode).toBe(0);
});

test("process.permission.has supports filesystem scopes and host wildcards", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-read=/tmp",
    "--allow-net=*.example.com",
    "--allow-env=NODE_*",
    "-e",
    "console.log(JSON.stringify([process.permission.has('fs.read', '/tmp/example.txt'), process.permission.has('fs.read', '/private/other.txt'), process.permission.has('net', 'api.example.com'), process.permission.has('net', 'example.com'), process.permission.has('env', 'NODE_ENV'), process.permission.has('env', 'HOME')]))",
  ]);
  expect(result.stdout).toBe("[true,false,true,false,true,false]\n");
  expect(result.exitCode).toBe(0);
});

test("experimental environment permissions filter reads", async () => {
  const result = await run(
    [
      "--experimental-permissions",
      "--secure",
      "--allow-env=PERMISSION_SECRET",
      "-e",
      "console.log(process.env.PERMISSION_SECRET ?? 'denied')",
    ],
    { ...bunEnv, PERMISSION_SECRET: "visible" },
  );
  expect(result.stdout).toBe("visible\n");
  expect(result.exitCode).toBe(0);

  const denied = await run(
    ["--experimental-permissions", "--secure", "-e", "console.log(process.env.PERMISSION_SECRET ?? 'denied')"],
    { ...bunEnv, PERMISSION_SECRET: "hidden" },
  );
  expect(denied.stdout).toBe("denied\n");
  expect(denied.exitCode).toBe(0);
});

test("experimental network permissions reject disallowed fetches", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-net=api.example.com",
    "-e",
    "fetch('http://127.0.0.1:1/').then(() => console.log('unexpected')).catch(error => console.log(error.message))",
  ]);
  expect(result.stdout).toContain("Network permission denied: 127.0.0.1");
  expect(result.stdout).not.toContain("unexpected");
  expect(result.exitCode).toBe(0);
});

test("subprocess helper forwards its environment", async () => {
  const result = await run(["-e", "console.log(process.env.PERMISSION_FIXTURE)"], {
    ...bunEnv,
    PERMISSION_FIXTURE: "forwarded",
  });
  expect(result).toEqual({ stdout: "forwarded\n", stderr: "", exitCode: 0 });
});

test.each(["w+", "a+", "r+"])("readFile requires a write grant for flag %s", async flag => {
  using directory = tempDir("permission-read-flags", { "file.txt": "preserve" });
  const filename = join(String(directory), "file.txt");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${filename}`,
    "-e",
    `try { require('fs').readFileSync(${JSON.stringify(filename)}, { flag: ${JSON.stringify(flag)} }); console.log('unexpected'); }
     catch (error) { console.log(error.code); }`,
  ]);
  expect(result.stdout).toBe("EACCES\n");
  expect(await Bun.file(filename).text()).toBe("preserve");
  expect(result.exitCode).toBe(0);
});

test("permission queries enforce lexical boundaries and case-insensitive host wildcards", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-read=/allowed/",
    "--allow-net=*.EXAMPLE.com",
    "-e",
    `console.log(JSON.stringify([
      process.permission.has('fs.read', '/allowed/file'),
      process.permission.has('fs.read', '/allowed-other/file'),
      process.permission.has('fs.read', '/allowed/../outside'),
      process.permission.has('net', 'api.example.COM'),
      process.permission.has('net', 'example.com')
    ]))`,
  ]);
  expect(result.stdout).toBe("[true,false,false,true,false]\n");
  expect(result.exitCode).toBe(0);
});

test("filesystem root grant includes descendants", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-read=/",
    "-e",
    "console.log(process.permission.has('fs.read', '/child/file'))",
  ]);
  expect(result.stdout).toBe("true\n");
  expect(result.exitCode).toBe(0);
});

test("restricted network grants do not automatically follow redirects", async () => {
  let destinationRequests = 0;
  using destination = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      destinationRequests++;
      return new Response("destination");
    },
  });
  using source = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      return Response.redirect(`http://localhost:${destination.port}/`, 302);
    },
  });
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-net=127.0.0.1",
    "-e",
    `try { await fetch(${JSON.stringify(source.url.href)}, { proxy: false }); console.log('unexpected'); }
     catch { console.log('redirect rejected'); }`,
  ]);
  expect(result.stdout).toBe("redirect rejected\n");
  expect(destinationRequests).toBe(0);
  expect(result.exitCode).toBe(0);
  const manual = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-net=127.0.0.1",
    "-e",
    `const response = await fetch(${JSON.stringify(source.url.href)}, { proxy: false, redirect: 'manual' }); console.log(response.status);`,
  ]);
  expect(manual.stdout).toBe("302\n");
  expect(destinationRequests).toBe(0);
  expect(manual.exitCode).toBe(0);

  for (const grants of [[], ["--experimental-permissions", "--secure", "--allow-net=*"]]) {
    const unrestricted = await run([
      ...grants,
      "-e",
      `const response = await fetch(${JSON.stringify(source.url.href)}, { proxy: false }); console.log(await response.text());`,
    ]);
    expect(unrestricted.stdout).toBe("destination\n");
    expect(unrestricted.exitCode).toBe(0);
  }
  expect(destinationRequests).toBe(2);
});

test.each(["readFileSync", "readFile"])("%s rejects write-capable flags before mutation", async operation => {
  using directory = tempDir("permission-read-entrypoints", { "file.txt": "preserve" });
  const filename = join(String(directory), "file.txt");
  const read =
    operation === "readFileSync"
      ? `require('fs').readFileSync(${JSON.stringify(filename)}, { flag: 'w+' })`
      : `await require('fs/promises').readFile(${JSON.stringify(filename)}, { flag: 'w+' })`;
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${filename}`,
    "-e",
    `try { ${read}; console.log('unexpected'); } catch (error) { console.log(error.code); }`,
  ]);
  expect(result.stdout).toBe("EACCES\n");
  expect(await Bun.file(filename).text()).toBe("preserve");
  expect(result.exitCode).toBe(0);
});

test("write grants permit writes and reject sibling paths", async () => {
  using directory = tempDir("permission-write-paths", { "allowed.txt": "before", "denied.txt": "preserve" });
  const allowedPath = join(String(directory), "allowed.txt");
  const deniedPath = join(String(directory), "denied.txt");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-write=${allowedPath}`,
    "-e",
    `const fs = require('fs'); fs.writeFileSync(${JSON.stringify(allowedPath)}, 'after');
     try { fs.writeFileSync(${JSON.stringify(deniedPath)}, 'unexpected'); } catch (error) { console.log(error.code); }`,
  ]);
  expect(result.stdout).toBe("EACCES\n");
  expect(await Bun.file(allowedPath).text()).toBe("after");
  expect(await Bun.file(deniedPath).text()).toBe("preserve");
  expect(result.exitCode).toBe(0);
});

test.each(["read", "write"])("empty %s grant does not authorize absolute paths", async scope => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-${scope}=`,
    "-e",
    `console.log(process.permission.has('fs.${scope}', '/child/file'))`,
  ]);
  expect(result.stdout).toBe("false\n");
  expect(result.exitCode).toBe(0);
});
