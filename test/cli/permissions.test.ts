import { expect, test } from "bun:test";
import { bunEnv, bunExe, isDebug, tempDir } from "harness";
import { chmod, readdir, realpath, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";

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

test("filesystem permission warning describes the trusted-code boundary", async () => {
  const result = await run(["--experimental-permissions", "--secure", "--allow-read=/tmp", "-e", "console.log('ran')"]);
  expect(result.stdout).toBe("ran\n");
  expect(result.stderr).toContain(
    "experimental filesystem permissions constrain trusted application code; use an OS security boundary for hostile code",
  );
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
    "fetch('http://127.0.0.1:1/', {proxy:false}).then(() => console.log('unexpected')).catch(error => console.log(error.code))",
  ]);
  expect(result.stdout).toBe("AccessDenied\n");
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

test.each(["read", "write"])("empty %s grant is rejected before execution", async scope => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-${scope}=`,
    "-e",
    `console.log(process.permission.has('fs.${scope}', '/child/file'))`,
  ]);
  expect(result.stdout).toBe("");
  expect(result.stderr).toContain("invalid filesystem grant");
  expect(result.exitCode).toBe(1);
});

test("restricted environment mediates aliases, cached reads, reflection, and mutations", async () => {
  const result = await run(
    [
      "--experimental-permissions",
      "--allow-env=PERMISSION_ALLOWED*",
      "--allow-env=456",
      "-e",
      `
      export {};
      const assert = (value, label) => { if (!value) throw new Error(label); };
      const aliases = [process.env, Bun.env, import.meta.env];
      const denied = ['PERMISSION_DENIED', '123', 'TZ', 'NODE_TLS_REJECT_UNAUTHORIZED', 'BUN_CONFIG_VERBOSE_FETCH', 'HTTP_PROXY'];
      Object.prototype.PERMISSION_DENIED = 'polluted';
      process.permission.has = () => true;
      for (const env of aliases) {
        assert(env === aliases[0], 'alias identity');
        assert(Object.getPrototypeOf(env) === null, 'restricted prototype');
        assert(env.PERMISSION_ALLOWED === 'visible', 'first read');
        assert(env.PERMISSION_ALLOWED === 'visible', 'cached read');
        assert(env[456] === 'numeric-visible', 'numeric read');
        for (const key of denied) {
          assert(env[key] === undefined, 'denied read ' + key);
          assert(!(key in env), 'denied has ' + key);
          assert(Object.getOwnPropertyDescriptor(env, key) === undefined, 'denied descriptor ' + key);
          for (const keys of [Object.keys(env), Object.getOwnPropertyNames(env), Reflect.ownKeys(env)]) {
            assert(!keys.includes(key), 'denied enumeration ' + key);
          }
          let coerced = false;
          const value = {toString() { coerced = true; return 'changed'; }};
          for (const mutate of [
            () => { env[key] = value; },
            () => Reflect.set(env, key, value),
            () => { delete env[key]; },
            () => Object.defineProperty(env, key, {value, configurable:true}),
            () => Reflect.defineProperty(env, key, {get() {return 'changed';}, configurable:true}),
          ]) {
            let error;
            try { mutate(); } catch (caught) { error = caught; }
            assert(error instanceof TypeError && error.message === 'Environment permission denied', 'denied mutation ' + key);
          }
          assert(!coerced, 'denied value coercion ' + key);
        }
        for (const mutate of [() => Object.setPrototypeOf(env, {}), () => Reflect.setPrototypeOf(env, {})]) {
          let error;
          try { mutate(); } catch (caught) { error = caught; }
          assert(error instanceof TypeError && error.message === 'Environment permission denied', 'prototype mutation');
        }
        assert(!JSON.stringify({...env}).includes('hidden-environment-marker'), 'spread disclosure');
        assert(!JSON.stringify(env).includes('hidden-environment-marker'), 'JSON disclosure');
        assert(!require('node:util').inspect(env, {showProxy:true}).includes('hidden-environment-marker'), 'inspect disclosure');
      }
      delete Object.prototype.PERMISSION_DENIED;
      process.env.PERMISSION_ALLOWED_WRITE = 'changed';
      assert(Bun.env.PERMISSION_ALLOWED_WRITE === 'changed', 'allowed assignment');
      Object.defineProperty(Bun.env, 'PERMISSION_ALLOWED_WRITE', {value:'defined', configurable:true});
      assert(process.env.PERMISSION_ALLOWED_WRITE === 'defined', 'allowed define');
      delete process.env.PERMISSION_ALLOWED_WRITE;
      assert(process.env.PERMISSION_ALLOWED_WRITE === undefined, 'allowed delete');
      console.log('environment matrix passed');
      `,
    ],
    {
      ...bunEnv,
      PERMISSION_ALLOWED: "visible",
      PERMISSION_DENIED: "hidden-environment-marker",
      "123": "hidden-environment-marker",
      "456": "numeric-visible",
      TZ: "UTC",
      NODE_TLS_REJECT_UNAUTHORIZED: "1",
      BUN_CONFIG_VERBOSE_FETCH: "0",
      HTTP_PROXY: "http://hidden-environment-marker.invalid",
    },
  );
  expect(result.stdout, result.stderr).toBe("environment matrix passed\n");
  expect(result.exitCode).toBe(0);
});

test("granted workers retain environment authority with explicit env and empty execArgv", async () => {
  using directory = tempDir("permission-worker", {
    "worker.js": `
      const {parentPort} = require('node:worker_threads');
      parentPort.postMessage([
        process.env.PERMISSION_ALLOWED,
        process.env.PERMISSION_DENIED ?? null,
        process.permission.has('env', 'PERMISSION_DENIED'),
        Object.keys(process.env).includes('PERMISSION_DENIED')
      ]);
    `,
  });
  const result = await run([
    "--experimental-permissions",
    "--allow-worker",
    "--allow-env=PERMISSION_ALLOWED",
    `--allow-read=${directory}`,
    "-e",
    `
      const {Worker} = require('node:worker_threads');
      const worker = new Worker(${JSON.stringify(join(String(directory), "worker.js"))}, {
        execArgv: [], env: {PERMISSION_ALLOWED:'visible', PERMISSION_DENIED:'hidden'}
      });
      let result;
      try { result = await new Promise((resolve, reject) => {worker.once('message',resolve); worker.once('error',reject);}); }
      finally { await worker.terminate(); }
      console.log(JSON.stringify(result));
    `,
  ]);
  expect(result.stdout).toBe('["visible",null,false,false]\n');
  expect(result.exitCode).toBe(0);
});

test("capability grants permit subprocess, FFI, Inspector, and system APIs explicitly", async () => {
  const cases = [
    {
      flag: "--allow-run",
      script: `const child = Bun.spawnSync([${JSON.stringify(bunExe())}, '-e', "console.log('child ran')"]); if (child.exitCode !== 0) throw new Error(child.stderr.toString()); console.log(child.stdout.toString().trim());`,
      output: "child ran\n",
      denied: /[Ss]ubprocess permission denied/,
      extra: [],
    },
    {
      flag: "--allow-ffi",
      script: `const {ptr} = require('bun:ffi'); const bytes = new Uint8Array([7]); console.log(ptr(bytes) > 0);`,
      output: "true\n",
      denied: /FFI permission denied/,
      extra: [],
    },
    {
      flag: "--allow-inspector",
      script: "console.log('inspector ran')",
      output: "inspector ran\n",
      denied: "Inspector access requires --allow-inspector under a restricted permission policy",
      extra: ["--inspect=0"],
    },
    {
      flag: "--allow-sys",
      script: "console.log(typeof require('node:os').hostname() === 'string')",
      output: "true\n",
      denied: /System information permission denied/,
      extra: [],
    },
  ];
  const results = await Promise.all(
    cases.map(async entry => ({
      entry,
      denied: await run([
        "--experimental-permissions",
        "--allow-env=PERMISSION_ALLOWED",
        ...entry.extra,
        "-e",
        entry.script,
      ]),
      allowed: await run([
        "--experimental-permissions",
        "--allow-env=PERMISSION_ALLOWED",
        entry.flag,
        ...entry.extra,
        "-e",
        entry.script,
      ]),
    })),
  );
  for (const { entry, denied, allowed } of results) {
    expect(denied.stdout).toBe("");
    expect(denied.stderr).toMatch(entry.denied);
    expect(denied.exitCode).not.toBe(0);
    expect(allowed.stdout).toBe(entry.output);
    expect(allowed.exitCode).toBe(0);
  }
}, 30000);

test("worker capability is denied before its source executes", async () => {
  const result = await run([
    "--experimental-permissions",
    "--allow-env=PERMISSION_ALLOWED",
    "-e",
    "new Worker('data:text/javascript,console.log(\"worker ran\")')",
  ]);
  expect(result.stdout).toBe("");
  expect(result.stderr).toMatch(/[Ww]orker permission denied/);
  expect(result.exitCode).not.toBe(0);
});

test("exact network endpoints authorize each redirect hop", async () => {
  let destinationRequests = 0;
  let sourceRequests = 0;
  const destination = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      destinationRequests++;
      return new Response("destination");
    },
  });
  const source = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      sourceRequests++;
      return Response.redirect(destination.url.href, 302);
    },
  });
  let results;
  try {
    results = await Promise.all([
      run([
        "--experimental-permissions",
        `--allow-net=127.0.0.1:${source.port}`,
        "-e",
        `try { await fetch(${JSON.stringify(destination.url.href)}, {proxy:false}); console.log('unexpected'); } catch (error) { console.log(error.code); }`,
      ]),
      run([
        "--experimental-permissions",
        `--allow-net=127.0.0.1:${source.port}`,
        "-e",
        `try { await fetch(${JSON.stringify(source.url.href)}, {proxy:false}); console.log('unexpected'); } catch (error) { console.log(error.code); }`,
      ]),
      run([
        "--experimental-permissions",
        `--allow-net=127.0.0.1:${source.port}`,
        `--allow-net=127.0.0.1:${destination.port}`,
        "-e",
        `console.log(await (await fetch(${JSON.stringify(source.url.href)}, {proxy:false})).text())`,
      ]),
    ]);
  } finally {
    await Promise.all([source.stop(true), destination.stop(true)]);
  }
  expect(results[0].stdout).toBe("AccessDenied\n");
  expect(results[1].stdout).toBe("AccessDenied\n");
  expect(results[2].stdout).toBe("destination\n");
  expect(results.map(result => result.exitCode)).toEqual([0, 0, 0]);
  expect(sourceRequests).toBe(2);
  expect(destinationRequests).toBe(1);
});

test("explicit proxies require authority for both proxy and destination", async () => {
  let proxyRequests = 0;
  let destinationRequests = 0;
  const destination = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      destinationRequests++;
      return new Response("direct");
    },
  });
  const proxy = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch() {
      proxyRequests++;
      return new Response("proxy");
    },
  });
  let results;
  try {
    // Explicit proxies also honor NO_PROXY; isolate this transport fixture from host settings.
    const script = `process.env.NO_PROXY = ''; process.env.no_proxy = ''; try { console.log(await (await fetch(${JSON.stringify(destination.url.href)}, {proxy:${JSON.stringify(proxy.url.href)}})).text()); } catch(error) { console.log(error.code); }`;
    results = await Promise.all([
      run(["--experimental-permissions", `--allow-net=127.0.0.1:${destination.port}`, "-e", script]),
      run(["--experimental-permissions", `--allow-net=127.0.0.1:${proxy.port}`, "-e", script]),
      run([
        "--experimental-permissions",
        `--allow-net=127.0.0.1:${proxy.port}`,
        `--allow-net=127.0.0.1:${destination.port}`,
        "-e",
        script,
      ]),
    ]);
  } finally {
    await Promise.all([proxy.stop(true), destination.stop(true)]);
  }
  expect(results[0].stdout).toBe("AccessDenied\n");
  expect(results[1].stdout).toBe("AccessDenied\n");
  expect(results[2].stdout).toBe("proxy\n");
  expect(results.map(result => result.exitCode)).toEqual([0, 0, 0]);
  expect(proxyRequests).toBe(1);
  expect(destinationRequests).toBe(0);
});

test("filesystem metadata, mutation, Blob, and descriptor paths enforce grants", async () => {
  using directory = tempDir("permission-filesystem-matrix", {
    "allowed.txt": "readable",
    "denied.txt": "preserve",
  });
  const allowed = join(String(directory), "allowed.txt");
  const denied = join(String(directory), "denied.txt");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${allowed}`,
    "-e",
    `
      const fs = require('node:fs');
      const allowed = ${JSON.stringify(allowed)}, denied = ${JSON.stringify(denied)};
      const assert = (value, label) => { if (!value) throw new Error(label); };
      const reject = async (name, operation) => {
        let failure;
        try { await operation(); } catch (error) { failure = error; }
        assert(failure && (failure.code === 'EACCES' || /[Pp]ermission denied|AccessDenied/.test(failure.message)), name);
      };
      for (const [name, operation] of [
        ['stat', () => fs.statSync(denied)],
        ['lstat', () => fs.lstatSync(denied)],
        ['access', () => fs.accessSync(denied)],
        ['realpath', () => fs.realpathSync(denied)],
        ['readdir', () => fs.readdirSync(${JSON.stringify(String(directory))})],
        ['unlink', () => fs.unlinkSync(denied)],
        ['rename', () => fs.renameSync(denied, denied+'.moved')],
        ['chmod', () => fs.chmodSync(denied, 0o600)],
        ['truncate', () => fs.truncateSync(denied, 0)],
        ['mkdir', () => fs.mkdirSync(denied+'.directory')],
        ['async stat', () => fs.promises.stat(denied)],
        ['Blob text', () => Bun.file(denied).text()],
        ['Blob arrayBuffer', () => Bun.file(denied).arrayBuffer()],
        ['Bun.write', () => Bun.write(denied, 'changed')],
      ]) await reject(name, operation);
      assert(await Bun.file(allowed).text() === 'readable', 'allowed Blob read');
      const descriptor = fs.openSync(allowed, 'r');
      try {
        assert(fs.fstatSync(descriptor).size === 8, 'allowed descriptor metadata');
        assert(fs.readFileSync(descriptor, 'utf8') === 'readable', 'allowed descriptor read');
        await reject('descriptor write', () => fs.writeSync(descriptor, 'changed'));
        await reject('descriptor truncate', () => fs.ftruncateSync(descriptor, 0));
        await reject('descriptor Bun.write', () => Bun.write(descriptor, 'changed'));
      } finally { fs.closeSync(descriptor); }
      console.log('filesystem matrix passed');
    `,
  ]);
  expect(result.stdout).toBe("filesystem matrix passed\n");
  expect(await Bun.file(allowed).text()).toBe("readable");
  expect(await Bun.file(denied).text()).toBe("preserve");
  expect(await Bun.file(`${denied}.moved`).exists()).toBe(false);
  expect(await Bun.file(`${denied}.directory`).exists()).toBe(false);
  expect(result.exitCode).toBe(0);
});

test("symlink entries remain distinct from targets during recursive filesystem operations", async () => {
  using directory = tempDir("permission-symlink-matrix", {
    "allowed/source/nested/file.txt": "copyable",
    "allowed/linked-source/own.txt": "own",
    "outside/secret.txt": "outside-secret",
  });
  const allowed = join(String(directory), "allowed");
  const outside = join(String(directory), "outside");
  const link = join(allowed, "link");
  await symlink(outside, link, "junction");
  await symlink(outside, join(allowed, "linked-source", "outside"), "junction");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${allowed}`,
    `--allow-write=${allowed}`,
    "-e",
    `
      const fs = require('node:fs');
      const allowed = ${JSON.stringify(allowed)}, link = ${JSON.stringify(link)};
      const assert = (value, label) => { if (!value) throw new Error(label); };
      const reject = async (name, operation) => {
        let failure;
        try { await operation(); } catch (error) { failure = error; }
        assert(failure && (failure.code === 'EACCES' || /[Pp]ermission denied/.test(failure.message)), name);
      };
      assert(fs.lstatSync(link).isSymbolicLink(), 'allowed link metadata');
      assert(typeof fs.readlinkSync(link) === 'string', 'allowed link entry read');
      await reject('target metadata', () => fs.statSync(link));
      await reject('target Blob read', () => Bun.file(link+'/secret.txt').text());
      fs.cpSync(allowed+'/source', allowed+'/copy', {recursive:true});
      assert(fs.readFileSync(allowed+'/copy/nested/file.txt','utf8') === 'copyable', 'allowed recursive copy');
      assert(fs.readdirSync(allowed+'/source',{recursive:true}).length === 2, 'allowed recursive listing');
      await reject('denied recursive child', () => fs.cpSync(allowed+'/linked-source', allowed+'/rejected-copy', {recursive:true,dereference:true}));
      fs.unlinkSync(link);
      console.log('symlink matrix passed');
    `,
  ]);
  expect(result.stdout).toBe("symlink matrix passed\n");
  expect(await Bun.file(join(outside, "secret.txt")).text()).toBe("outside-secret");
  expect(await Bun.file(join(allowed, "copy", "nested", "file.txt")).text()).toBe("copyable");
  expect(await Bun.file(join(allowed, "rejected-copy", "outside", "secret.txt")).exists()).toBe(false);
  expect(result.exitCode).toBe(0);
});

test("bundler inline and prefix modes omit denied native environment values", async () => {
  using directory = tempDir("permission-bundler-env", {
    "entry.js": "console.log(process.env.PERMISSION_ALLOWED, process.env.PERMISSION_DENIED);",
  });
  const result = await run(
    [
      "--experimental-permissions",
      "--allow-env=PERMISSION_ALLOWED",
      "-e",
      `
      for (const env of ['inline', 'PERMISSION_*']) {
        const build = await Bun.build({entrypoints:[${JSON.stringify(join(String(directory), "entry.js"))}], env});
        if (!build.success) throw new AggregateError(build.logs, 'build failed');
        const output = await build.outputs[0].text();
        if (!output.includes('allowed-build-marker')) throw new Error('allowed variable not inlined');
        if (output.includes('denied-build-marker')) throw new Error('denied variable inlined');
      }
      console.log('bundler environment passed');
    `,
    ],
    { ...bunEnv, PERMISSION_ALLOWED: "allowed-build-marker", PERMISSION_DENIED: "denied-build-marker" },
  );
  expect(result.stdout).toBe("bundler environment passed\n");
  expect(result.exitCode).toBe(0);
});

test("S3 presigning filters native environment credentials and preserves explicit values", async () => {
  const script = `
    const client = new Bun.S3Client({accessKeyId:'explicit-key', secretAccessKey:'explicit-secret', region:'us-east-1', bucket:'bucket', virtualHostedStyle:true});
    const url = new URL(client.presign('file.txt'));
    console.log(JSON.stringify([url.searchParams.get('X-Amz-Credential').split('/')[0],url.searchParams.get('X-Amz-Security-Token')]));
  `;
  const env = { ...bunEnv, AWS_ACCESS_KEY_ID: "denied-key", AWS_SESSION_TOKEN: "session-marker" };
  const results = await Promise.all([
    run(["--experimental-permissions", "--allow-env=PERMISSION_ALLOWED", "-e", script], env),
    run(["--experimental-permissions", "--allow-env=AWS_SESSION_TOKEN", "-e", script], env),
  ]);
  expect(results[0].stdout).toBe('["explicit-key",null]\n');
  expect(results[1].stdout).toBe('["explicit-key","session-marker"]\n');
  expect(results.map(result => result.exitCode)).toEqual([0, 0]);
});

test("Redis native URL defaults honor each environment grant before parsing", async () => {
  const script = `try { const client = new Bun.RedisClient(); client.close(); console.log('default accepted'); } catch(error) { console.log(error.message); }`;
  const env = { ...bunEnv, REDIS_URL: "invalid://redis-secret", VALKEY_URL: "invalid://valkey-secret" };
  const results = await Promise.all(
    ["PERMISSION_ALLOWED", "REDIS_URL", "VALKEY_URL"].map(key =>
      run(["--experimental-permissions", `--allow-env=${key}`, "-e", script], env),
    ),
  );
  expect(results[0].stdout).toBe("default accepted\n");
  expect(results[1].stdout).toContain("Expected url protocol");
  expect(results[2].stdout).toContain("Expected url protocol");
  expect(results.map(result => result.exitCode)).toEqual([0, 0, 0]);
});

test("system information grants do not disclose denied native environment defaults", async () => {
  const script = "const os=require('node:os'); console.log(JSON.stringify([os.homedir(),os.userInfo()]));";
  const env = {
    ...bunEnv,
    HOME: "/permission-hidden-home",
    USERPROFILE: "C:\\permission-hidden-profile",
    USER: "permission-hidden-user",
    SHELL: "/permission-hidden-shell",
  };
  const results = await Promise.all([
    run(["--experimental-permissions", "--allow-sys", "--allow-env=PERMISSION_ALLOWED", "-e", script], env),
    run(
      [
        "--experimental-permissions",
        "--allow-sys",
        "--allow-env=HOME",
        "--allow-env=USERPROFILE",
        "--allow-env=USER",
        "--allow-env=SHELL",
        "-e",
        script,
      ],
      env,
    ),
  ]);
  expect(results[0].stdout).not.toContain("permission-hidden-");
  expect(results[1].stdout).toContain("permission-hidden-user");
  expect(results[1].stdout).toContain(
    process.platform === "win32" ? "permission-hidden-profile" : "permission-hidden-home",
  );
  expect(results.map(result => result.exitCode)).toEqual([0, 0]);
});

test("server defaults ignore denied environment variables and preserve explicit options", async () => {
  const reserved = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("reserved") });
  let result;
  try {
    result = await run(
      [
        "--experimental-permissions",
        "--allow-env=PERMISSION_ALLOWED",
        "--port=0",
        "-e",
        `
        const server = Bun.serve({hostname:'127.0.0.1',fetch:() => new Response('ok')});
        const first = [server.port !== ${reserved.port}, server.development];
        await server.stop(true);
        const explicit = Bun.serve({hostname:'127.0.0.1',port:0,development:false,fetch:() => new Response('ok')});
        const second = explicit.development;
        await explicit.stop(true);
        console.log(JSON.stringify([first,second]));
      `,
      ],
      {
        ...bunEnv,
        NODE_ENV: "production",
        BUN_PORT: String(reserved.port),
        PORT: String(reserved.port),
        NODE_PORT: String(reserved.port),
      },
    );
  } finally {
    await reserved.stop(true);
  }
  expect(result.stdout).toBe("[[true,true],false]\n");
  expect(result.exitCode).toBe(0);
});

// Release builds do not contain the optional source-dump feature.
test.skipIf(!isDebug)("restricted writes skip optional debug source dumps", async () => {
  using directory = tempDir("permission-debug-dump", { "entry.ts": "const value: number = 42; console.log(value);" });
  const canonicalDirectory = await realpath(String(directory));
  const source = join(canonicalDirectory, "entry.ts");
  const dumpRoot =
    process.platform === "win32"
      ? join(tmpdir(), "bun-debug-src")
      : process.platform === "android"
        ? "/data/local/tmp/bun-debug-src"
        : "/tmp/bun-debug-src";
  const dumpDirectory = join(dumpRoot, canonicalDirectory.slice(parse(canonicalDirectory).root.length));
  let unrestricted;
  let restricted;
  let initialDump = false;
  let restrictedDump = false;
  try {
    unrestricted = await run(["-e", `await import(${JSON.stringify(source)})`], { ...bunEnv, BUN_DEBUG_NO_DUMP: "0" });
    initialDump = await Bun.file(join(dumpDirectory, "entry.ts")).exists();
    await rm(dumpDirectory, { recursive: true, force: true });
    restricted = await run(
      [
        "--experimental-permissions",
        `--allow-write=${join(canonicalDirectory, "permitted-output")}`,
        "-e",
        `await import(${JSON.stringify(source)})`,
      ],
      { ...bunEnv, BUN_DEBUG_NO_DUMP: "0" },
    );
    restrictedDump = await Bun.file(join(dumpDirectory, "entry.ts")).exists();
  } finally {
    await rm(dumpDirectory, { recursive: true, force: true });
  }
  expect(unrestricted.stdout).toBe("42\n");
  expect(restricted.stdout).toBe("42\n");
  expect(initialDump).toBe(true);
  expect(restrictedDump).toBe(false);
  expect([unrestricted.exitCode, restricted.exitCode]).toEqual([0, 0]);
});

test.concurrent("SQLite memory databases remain usable with no filesystem grants", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "-e",
    `
      const {Database} = require('bun:sqlite');
      const db = new Database(':memory:');
      db.exec('CREATE TABLE values_table(value); INSERT INTO values_table VALUES(42)');
      const restored = Database.deserialize(db.serialize());
      console.log(restored.query('SELECT value FROM values_table').get().value);
      restored.close(); db.close();
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("42\n");
  expect(result.exitCode).toBe(0);
});

test.concurrent("SQLite grants allow transactions, WAL, mmap fallback and readonly reopen", async () => {
  using directory = tempDir("permission-sqlite-allowed", {});
  const database = join(String(directory), "database.sqlite");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${directory}`,
    `--allow-write=${directory}`,
    "-e",
    `
      const {Database} = require('bun:sqlite');
      const filename = ${JSON.stringify(database)};
      const db = new Database(filename);
      const mode = db.query('PRAGMA journal_mode=WAL').get();
      if (mode.journal_mode !== 'wal') throw new Error('WAL unavailable');
      db.exec('PRAGMA mmap_size=1048576; CREATE TABLE values_table(value)');
      db.transaction(() => db.exec('INSERT INTO values_table VALUES(42)'))();
      if (db.query('SELECT value FROM values_table').get().value !== 42) throw new Error('WAL read failed');
      db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      db.close();
      const reader = new Database(filename, {readonly:true});
      console.log(reader.query('SELECT value FROM values_table').get().value);
      reader.close();
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("42\n");
  expect(result.exitCode).toBe(0);
  expect(await Bun.file(database).exists()).toBe(true);
});

test.concurrent("SQLite denies main files, ATTACH, VACUUM and native VFS URI bypass without artifacts", async () => {
  using directory = tempDir("permission-sqlite-denied", { "allowed/keep": "", "outside/keep": "" });
  const allowed = join(String(directory), "allowed");
  const outside = join(String(directory), "outside");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${allowed}`,
    `--allow-write=${allowed}`,
    "-e",
    `
      const {Database, constants} = require('bun:sqlite');
      const outside = ${JSON.stringify(outside)}, allowed = ${JSON.stringify(allowed)};
      const reject = (label, operation) => {
        try { operation(); } catch { return; }
        throw new Error(label + ' unexpectedly succeeded');
      };
      for (let attempt = 0; attempt < 20; attempt++) {
        reject('main open', () => new Database(outside+'/main.sqlite'));
      }
      const db = new Database(':memory:', constants.SQLITE_OPEN_READWRITE | constants.SQLITE_OPEN_CREATE | constants.SQLITE_OPEN_URI);
      reject('ATTACH', () => db.query('ATTACH DATABASE ? AS forbidden').run(outside+'/attach.sqlite'));
      reject('VACUUM INTO', () => db.query('VACUUM INTO ?').run(outside+'/vacuum.sqlite'));
      for (const vfs of ['unix', 'unix-none', 'win32']) {
        const uri = require('node:url').pathToFileURL(allowed+'/uri-'+vfs+'.sqlite').href+'?vfs='+vfs;
        reject('native VFS open', () => new Database(uri, constants.SQLITE_OPEN_READWRITE | constants.SQLITE_OPEN_CREATE | constants.SQLITE_OPEN_URI));
        reject('native VFS ATTACH', () => db.query('ATTACH DATABASE ? AS bypass').run(uri));
      }
      db.close();
      const retry = new Database(allowed+'/retry.sqlite');
      retry.exec('CREATE TABLE success(value); INSERT INTO success VALUES(42)');
      console.log(retry.query('SELECT value FROM success').get().value);
      retry.close();
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("42\n");
  expect(result.exitCode).toBe(0);
  expect(await readdir(outside)).toEqual(["keep"]);
  expect((await readdir(allowed)).filter(name => name.startsWith("uri-"))).toEqual([]);
});

test.concurrent("SQLite rejects sidecar writes outside an exact database grant", async () => {
  using directory = tempDir("permission-sqlite-sidecars", {});
  const filename = join(String(directory), "database.sqlite");
  const setup = await run([
    "-e",
    `
    const {Database} = require('bun:sqlite');
    const db = new Database(${JSON.stringify(filename)});
    db.exec('CREATE TABLE values_table(value); INSERT INTO values_table VALUES(1)'); db.close();
  `,
  ]);
  expect(setup.exitCode).toBe(0);
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${directory}`,
    `--allow-write=${filename}`,
    "-e",
    `
      const {Database} = require('bun:sqlite');
      const db = new Database(${JSON.stringify(filename)});
      let denied = false;
      try { db.exec('INSERT INTO values_table VALUES(2)'); } catch { denied = true; }
      if (!denied) throw new Error('journal creation escaped database grant');
      if (db.query('SELECT count(*) AS count FROM values_table').get().count !== 1) throw new Error('denied write changed database');
      db.close(); console.log('denied');
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("denied\n");
  expect(result.exitCode).toBe(0);
  expect(await readdir(String(directory))).toEqual(["database.sqlite"]);
});

test.concurrent("SQLite native extensions and custom libraries require native authority", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "-e",
    `
      const {Database} = require('bun:sqlite');
      const reject = operation => {
        let message = '';
        try { operation(); } catch (error) { message = String(error.message); }
        if (!/permission denied/i.test(message)) throw new Error('missing native permission denial: '+message);
      };
      reject(() => Database.setCustomSQLite('/permission-forbidden-library'));
      const db = new Database(':memory:');
      reject(() => db.loadExtension('/permission-forbidden-extension'));
      db.close(); console.log('denied');
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("denied\n");
  expect(result.exitCode).toBe(0);
});

test.skipIf(process.platform === "win32")(
  "trailing separators on symlink metadata cannot escape filesystem grants",
  async () => {
    using directory = tempDir("permission-symlink-trailing-separator", { "allowed/keep": "", "outside/keep": "" });
    const allowed = join(String(directory), "allowed");
    const outside = join(String(directory), "outside");
    const link = join(allowed, "link");
    await symlink(outside, link);
    const before = await stat(outside);
    const result = await run([
      "--experimental-permissions",
      "--secure",
      `--allow-read=${allowed}`,
      `--allow-write=${allowed}`,
      "-e",
      `
      const fs = require('node:fs');
      const link = ${JSON.stringify(link)};
      if (!fs.lstatSync(link).isSymbolicLink()) throw new Error('link entry denied');
      const reject = operation => {
        let denied = false;
        try { operation(); } catch (error) { denied = error.code === 'EACCES'; }
        if (!denied) throw new Error('trailing separator did not deny target');
      };
      reject(() => fs.lstatSync(link+'/'));
      reject(() => fs.lutimesSync(link+'/', 1, 1));
      console.log('denied');
    `,
    ]);
    expect(result.stdout).toBe("denied\n");
    expect(result.exitCode).toBe(0);
    const after = await stat(outside);
    expect(after.atimeMs).toBe(before.atimeMs);
    expect(after.mtimeMs).toBe(before.mtimeMs);
  },
);

test("Node TCP hostname authorization stays local to native lookup attempts", async () => {
  const listener = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      data() {},
      open(socket) {
        socket.end();
      },
    },
  });
  try {
    const result = await run([
      "--experimental-permissions",
      "--secure",
      `--allow-net=localhost:${listener.port}`,
      "-e",
      `
      const net = require('node:net');
      process.on('uncaughtException', error => { console.error('uncaught', error); process.exit(21); });
      process.on('unhandledRejection', error => { console.error('unhandled', error); process.exit(22); });
      const deadline = setTimeout(() => process.exit(23), 3000);
      const attempt = (options, allowed) => new Promise((resolve, reject) => {
        let connected = false, errors = 0;
        const socket = net.connect({port: ${listener.port}, ...options});
        socket.on('connect', () => { connected = true; socket.end(); });
        socket.on('error', () => errors++);
        socket.on('close', () => {
          if (connected !== allowed || errors !== (allowed ? 0 : 1)) reject(new Error('incorrect socket lifecycle'));
          else resolve();
        });
      });
      await attempt({host:'localhost', family:4, autoSelectFamily:false}, true);
      await attempt({host:'localhost', autoSelectFamily:true}, true);
      await attempt({host:'127.0.0.1'}, false);
      await attempt({host:'localhost', autoSelectFamily:false, lookup(host, options, callback) {
        callback(null, '127.0.0.1', 4);
      }}, false);
      await attempt({host:'localhost', autoSelectFamily:true, lookup(host, options, callback) {
        callback(null, [{address:'127.0.0.1', family:4}, {address:'::1', family:6}]);
      }}, false);
      const addresses = await Bun.dns.lookup('localhost');
      if (addresses.some(address => 'authorization' in address)) throw new Error('public DNS exposed authorization');
      clearTimeout(deadline); console.log('complete');
      `,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("complete\n");
  } finally {
    listener.stop(true);
  }
});

test("UDP endpoint grants permit replies and deny other destination ports", async () => {
  let deniedPackets = 0;
  const allowed = await Bun.udpSocket({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      data(socket, data, port, address) {
        socket.send(data, port, address);
      },
    },
  });
  const denied = await Bun.udpSocket({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      data() {
        deniedPackets++;
      },
    },
  });
  try {
    const result = await run([
      "--experimental-permissions",
      "--secure",
      "--allow-net=127.0.0.1:0",
      `--allow-net=127.0.0.1:${allowed.port}`,
      "-e",
      `
      const deadline = setTimeout(() => process.exit(23), 3000);
      let received;
      const reply = new Promise(resolve => { received = resolve; });
      const socket = await Bun.udpSocket({hostname:'127.0.0.1', port:0, socket:{data(socket, data) { received(data.toString()); }}});
      let blocked = false;
      try { socket.send('denied', ${denied.port}, '127.0.0.1'); } catch { blocked = true; }
      if (!blocked) throw new Error('denied UDP send accepted');
      socket.send('allowed', ${allowed.port}, '127.0.0.1');
      if (await reply !== 'allowed') throw new Error('bad UDP reply');
      socket.close(); clearTimeout(deadline); console.log('complete');
      `,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("complete\n");
    expect(deniedPackets).toBe(0);
  } finally {
    allowed.close();
    denied.close();
  }
});

test("DNS and WebSocket denial precede remote transport", async () => {
  let upgrades = 0;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request, server) {
      upgrades++;
      return server.upgrade(request) ? undefined : new Response();
    },
    websocket: { message() {} },
  });
  try {
    const result = await run([
      "--experimental-permissions",
      "--secure",
      "--allow-net=localhost:1",
      "-e",
      `
      const deadline = setTimeout(() => process.exit(23), 3000);
      let denied = false;
      try { await Bun.dns.lookup('permission-denied.invalid'); } catch { denied = true; }
      if (!denied) throw new Error('DNS denial missing');
      denied = false;
      try { require('node:dns').setServers(['192.0.2.1']); } catch { denied = true; }
      if (!denied) throw new Error('custom resolver denial missing');
      await new Promise((resolve, reject) => {
        try {
          const socket = new WebSocket('ws://127.0.0.1:${server.port}/');
          socket.onopen = () => { socket.close(); reject(new Error('WebSocket connected')); };
          socket.onerror = () => resolve();
        } catch { resolve(); }
      });
      clearTimeout(deadline); console.log('complete');
      `,
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("complete\n");
    expect(upgrades).toBe(0);
  } finally {
    server.stop(true);
  }
});

test("persistent cron and WebView deny subprocess effects before argument coercion", async () => {
  const result = await run([
    "--experimental-permissions",
    "--allow-env=PERMISSION_ALLOWED",
    "-e",
    `
    const reject = (operation, message) => {
      let error;
      try { operation(); } catch (caught) { error = caught; }
      if (!(error instanceof TypeError) || error.message !== message) throw new Error('unexpected denial: '+error);
    };
    reject(() => Bun.cron('/definitely-missing-permission-fixture.js', '* * * * *', 'permission-fixture'),
      'Subprocess permission denied for persistent cron scheduling');
    reject(() => Bun.cron.remove('permission-fixture'),
      'Subprocess permission denied for persistent cron removal');
    reject(() => new Bun.WebView({get width() { throw new Error('getter ran'); }}),
      'Subprocess permission denied for WebView');
    console.log('denied');
    `,
  ]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toBe("denied\n");
});

test.concurrent("Bun.which hides denied inherited PATH but accepts an explicit search path", async () => {
  const filename = process.platform === "win32" ? "permission-probe.cmd" : "permission-probe";
  using directory = tempDir("permission-which-environment", { [filename]: "#!/bin/sh\nexit 0\n" });
  const canonicalDirectory = await realpath(String(directory));
  const executable = join(canonicalDirectory, filename);
  await chmod(executable, 0o755);
  const script = `console.log(JSON.stringify([
    Bun.which('permission-probe'),
    Bun.which('permission-probe', {PATH:${JSON.stringify(canonicalDirectory)}}),
    Bun.which(${JSON.stringify(executable)})
  ]));`;
  const result = await run(
    ["--experimental-permissions", "--secure", `--allow-read=${canonicalDirectory}`, "-e", script],
    { ...bunEnv, PATH: canonicalDirectory },
  );
  expect(result.stdout).toBe(JSON.stringify([null, executable, executable]) + "\n");
  expect(result.exitCode).toBe(0);
});

test.concurrent("Bun.which skips denied candidates and permits an authorized candidate", async () => {
  const filename = process.platform === "win32" ? "permission-probe.cmd" : "permission-probe";
  using directory = tempDir("permission-which-candidates", {
    ["outside/" + filename]: "#!/bin/sh\nexit 0\n",
    ["allowed/" + filename]: "#!/bin/sh\nexit 0\n",
  });
  const canonicalDirectory = await realpath(String(directory));
  const allowed = join(canonicalDirectory, "allowed"),
    outside = join(canonicalDirectory, "outside");
  const executable = join(allowed, filename),
    denied = join(outside, filename);
  await Promise.all([chmod(executable, 0o755), chmod(denied, 0o755)]);
  const searchPath = outside + (process.platform === "win32" ? ";" : ":") + allowed;
  const result = await run(
    [
      "--experimental-permissions",
      "--secure",
      "--allow-env=PATH",
      `--allow-read=${allowed}`,
      "-e",
      `
      console.log(JSON.stringify([
        Bun.which('permission-probe'),
        Bun.which(${JSON.stringify(denied)}),
        Bun.which('permission-probe',{PATH:${JSON.stringify(outside)}})
      ]));
    `,
    ],
    { ...bunEnv, PATH: searchPath },
  );
  expect(result.stdout).toBe(JSON.stringify([executable, null, null]) + "\n");
  expect(result.exitCode).toBe(0);
});

test("denied FFI initialization throws safely on repeated direct and module access", async () => {
  const result = await run([
    "--experimental-permissions",
    "--allow-env=PERMISSION_ALLOWED",
    "-e",
    `
    import {version} from 'bun';
    if (version !== process.versions.bun) throw new Error('builtin Bun import failed');
    for (let attempt = 0; attempt < 2; attempt++) {
      for (const access of [() => Bun.FFI, () => require('bun:ffi')]) {
        let error;
        try { access(); } catch (caught) { error = caught; }
        if (!(error instanceof TypeError) || error.message !== 'FFI permission denied under a restricted policy') {
          throw new Error('FFI denial failed: '+error);
        }
      }
    }
    console.log('denied');
    `,
  ]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toBe("denied\n");
});

test.concurrent("build output grants permit existing ancestors without permitting sibling output", async () => {
  using directory = tempDir("permission-build-output", {
    "source/entry.js": 'export const message = "permission-output";',
    "existing/deep/keep": "",
  });
  const root = await realpath(String(directory));
  const output = join(root, "existing", "deep", "generated");
  const denied = join(root, "existing", "deep", "denied");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    `--allow-read=${root}`,
    `--allow-write=${output}`,
    "-e",
    `
      const entrypoint = ${JSON.stringify(join(root, "source", "entry.js"))};
      const output = ${JSON.stringify(output)};
      const build = await Bun.build({entrypoints:[entrypoint],outdir:output,naming:'nested/[name].[ext]'});
      if (!build.success) throw new AggregateError(build.logs, 'permitted build failed');
      if (build.outputs.length !== 1) throw new Error('missing build output');
      require('node:fs').mkdirSync(output+'/mkdir/a', {recursive:true});
      let denied = false;
      try {
        const other = await Bun.build({entrypoints:[entrypoint],outdir:${JSON.stringify(denied)}});
        denied = !other.success;
      } catch { denied = true; }
      if (!denied) throw new Error('sibling build output was permitted');
      console.log('output grants passed');
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("output grants passed\n");
  expect(result.exitCode).toBe(0);
  expect(await Bun.file(join(output, "nested", "entry.js")).text()).toContain("permission-output");
  expect(await readdir(join(output, "mkdir"))).toEqual(["a"]);
  expect(await readdir(join(root, "existing", "deep"))).not.toContain("denied");
});

for (const [flag, kind] of [
  ["--cpu-prof", "cpu"],
  ["--cpu-prof-md", "cpu"],
  ["--heap-prof", "heap"],
  ["--heap-prof-md", "heap"],
]) {
  test(`${flag} authorizes its output before creating files or directories`, async () => {
    using directory = tempDir("permission-profile-output", { "allowed/keep": "", "outside/keep": "" });
    const allowed = join(String(directory), "allowed");
    const outside = join(String(directory), "outside");
    const deniedDirectory = join(outside, "missing");
    const script = "const until = performance.now()+25; while(performance.now()<until) {}";
    const common = [
      "--experimental-permissions",
      "--secure",
      "--allow-read=*",
      `--allow-write=${allowed}`,
      flag,
      `--${kind}-prof-name=profile`,
    ];
    const denied = await run([...common, `--${kind}-prof-dir=${deniedDirectory}`, "-e", script]);
    expect(denied.stderr).toContain("AccessDenied");
    expect(await readdir(outside)).toEqual(["keep"]);
    const permitted = await run([...common, `--${kind}-prof-dir=${allowed}`, "-e", script]);
    expect(permitted.exitCode, permitted.stderr).toBe(0);
    expect(permitted.stderr).not.toContain("AccessDenied");
    expect((await stat(join(allowed, "profile"))).size).toBeGreaterThan(0);
  });
}

test("an exact profiler output grant cannot create ungranted ancestors", async () => {
  using directory = tempDir("permission-profile-ancestors", {});
  const outputDirectory = join(String(directory), "missing", "nested");
  const output = join(outputDirectory, "profile");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-read=*",
    `--allow-write=${output}`,
    "--cpu-prof-md",
    `--cpu-prof-dir=${outputDirectory}`,
    "--cpu-prof-name=profile",
    "-e",
    "const until = performance.now()+25; while(performance.now()<until) {}",
  ]);
  expect(result.stderr).toContain("AccessDenied");
  expect(await readdir(String(directory))).toEqual([]);
});

test("node:v8 writeHeapSnapshot cannot truncate a denied output", async () => {
  using directory = tempDir("permission-v8-snapshot", { "existing.snapshot": "unchanged" });
  const filename = join(String(directory), "existing.snapshot");
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "-e",
    `let code; try { require('node:v8').writeHeapSnapshot(${JSON.stringify(filename)}); } catch(error) { code=error.code; }
     if(code !== 'EACCES') throw new Error('snapshot write was not denied: '+code); console.log('denied');`,
  ]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toBe("denied\n");
  expect(await Bun.file(filename).text()).toBe("unchanged");
});

test.concurrent("secure mode keeps native capabilities denied with all resource wildcards", async () => {
  const result = await run([
    "--experimental-permissions",
    "--secure",
    "--allow-read=*",
    "--allow-write=*",
    "--allow-net=*",
    "--allow-env=*",
    "-e",
    `
      const scopes = ['run','worker','ffi','inspector','sys'];
      if (scopes.some(scope => process.permission.has(scope))) throw new Error('resource wildcard granted native capability');
      const reject = operation => {
        let denied = false;
        try { operation(); } catch (error) { denied = /permission denied/i.test(String(error)); }
        if (!denied) throw new Error('native capability was not denied');
      };
      reject(() => Bun.spawnSync([${JSON.stringify(bunExe())}, '-e', "console.log('forbidden child')"]));
      reject(() => require('bun:ffi').ptr(new Uint8Array([1])));
      console.log('capabilities denied');
    `,
  ]);
  expect(result.stdout, result.stderr).toBe("capabilities denied\n");
  expect(result.exitCode).toBe(0);
});

test.skipIf(process.platform === "win32")(
  "Unix HTTP authorizes socket paths and listener filesystem writes",
  async () => {
    // Keep sockaddr_un paths short on macOS as well as Linux.
    using directory = tempDir("pu", {});
    const allowedPath = join(String(directory), "a.sock");
    const deniedPath = join(String(directory), "d.sock");
    const noWritePath = join(String(directory), "w.sock");
    let deniedRequests = 0;
    const trustedServer = Bun.serve({
      unix: deniedPath,
      fetch() {
        deniedRequests++;
        return new Response("forbidden");
      },
    });
    try {
      const permitted = await run([
        "--experimental-permissions",
        "--secure",
        `--allow-net=unix:${allowedPath}`,
        `--allow-write=${allowedPath}`,
        "-e",
        `
      const deadline = setTimeout(() => process.exit(23), 3000);
      let requests = 0;
      const server = Bun.serve({unix:${JSON.stringify(allowedPath)}, fetch() { requests++; return new Response('allowed'); }});
      try {
        const response = await fetch('http://ungranted.invalid/', {unix:${JSON.stringify(allowedPath)}, proxy:false});
        if(await response.text() !== 'allowed' || requests !== 1) throw new Error('granted Unix transport failed');
        let code;
        try { await fetch('http://ungranted.invalid/', {unix:${JSON.stringify(deniedPath)}, proxy:false}); }
        catch(error) { code = error.code; }
        if(code !== 'AccessDenied') throw new Error('Unix destination denial missing: '+code);
        console.log('allowed');
      } finally { server.stop(true); clearTimeout(deadline); }
      `,
      ]);
      expect(permitted.exitCode).toBe(0);
      expect(permitted.stdout).toBe("allowed\n");
      expect(deniedRequests).toBe(0);

      const missingWrite = await run([
        "--experimental-permissions",
        "--secure",
        `--allow-net=unix:${noWritePath}`,
        "-e",
        `
      let denied = false;
      try {
        const server = Bun.serve({unix:${JSON.stringify(noWritePath)}, fetch() { return new Response(); }});
        server.stop(true);
      } catch { denied = true; }
      if(!denied) throw new Error('Unix listener started without filesystem write authority');
      console.log('denied');
      `,
      ]);
      expect(missingWrite.exitCode).toBe(0);
      expect(missingWrite.stdout).toBe("denied\n");
      expect(await readdir(String(directory))).not.toContain("w.sock");
    } finally {
      trustedServer.stop(true);
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "restricted network authority permits local files but rejects junction traversal",
  async () => {
    using directory = tempDir("permission-windows-paths", { "target/value.txt": "local" });
    const root = await realpath(String(directory));
    const target = join(root, "target");
    const junction = join(root, "junction");
    await symlink(target, junction, "junction");
    const result = await (async () => {
      try {
        return await run([
          "--experimental-permissions",
          "--secure",
          "--allow-read=*",
          "--allow-write=*",
          "-e",
          `
        const fs = require('node:fs');
        const file = ${JSON.stringify(join(target, "value.txt"))};
        if (fs.readFileSync(file, 'utf8') !== 'local') throw new Error('local read failed');
        const fd = fs.openSync(file, 'r');
        try {
          if (fs.readFileSync(fd, 'utf8') !== 'local') throw new Error('descriptor read failed');
        } finally { fs.closeSync(fd); }
        for (const path of [${JSON.stringify(junction)}, ${JSON.stringify(join(junction, "value.txt"))}]) {
          let denied = false;
          try { fs.statSync(path); } catch (error) { denied = error.code === 'EACCES'; }
          if (!denied) throw new Error('junction traversal permitted: ' + path);
        }
        const junction = ${JSON.stringify(junction)};
        if (!fs.lstatSync(junction).isSymbolicLink()) throw new Error('junction entry metadata failed');
        if (!fs.readlinkSync(junction)) throw new Error('junction entry read failed');
        let denied = false;
        try { fs.readFileSync(${JSON.stringify(join(junction, "value.txt"))}); }
        catch (error) { denied = error.code === 'EACCES'; }
        if (!denied) throw new Error('junction target read permitted');
        fs.unlinkSync(junction);
        console.log('local only');
        `,
        ]);
      } finally {
        await rm(junction, { force: true });
      }
    })();
    expect(result.stdout, result.stderr).toBe("local only\n");
    expect(result.exitCode).toBe(0);
  },
);
