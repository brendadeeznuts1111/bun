import { file } from "bun";
import { expect, spyOn, test } from "bun:test";
import { bunEnv, bunExe, tempDir, tempDirWithFiles, VerdaccioRegistry } from "harness";
import { join } from "path";

test("custom matcher runs", async () => {
  const dir = tempDirWithFiles("custom-matcher-preload-test-fixture", {
    "preload.ts": await file(join(import.meta.dir, "custom-matcher-preload-test-fixture-1.ts")).text(),
    "expect-extend.test.ts": await file(join(import.meta.dir, "custom-matcher-preload-test-fixture-2.ts")).text(),
    "bunfig.toml": `
[test]
preload = "./preload.ts"
        `,
    "package.json": JSON.stringify(
      {
        name: "custom-matcher-preload-test-fixture",
        version: "1.0.0",
      },
      null,
      2,
    ),
  });
  const { stdout, exitCode } = Bun.spawnSync({
    cmd: [bunExe(), "test", "expect-extend.test.ts"],
    cwd: dir,
    env: bunEnv,
    stderr: "inherit",
    stdout: "pipe",
    stdin: "inherit",
  });
  expect(stdout.toString().trim()).toContain("custom matcher test passed");
  expect(exitCode).toBe(0);
});

test.each([null, undefined, 1, "command", ["-e", 1]])("toRun rejects invalid command arguments: %p", received => {
  expect(() => expect(received).toRun()).toThrow("toRun expects an array of command arguments");
});

test.each([null, undefined, 1, "function", {}])("throw matchers reject nonfunctions: %p", async received => {
  expect(() => expect(received).toThrowWithCode(Error, "ERR_TEST")).toThrow("toThrowWithCode expects a function");
  await assertAsyncMatcherFailure(
    `expect(${JSON.stringify(received)}).toThrowWithCodeAsync(Error, "ERR_TEST")`,
    "TypeError: toThrowWithCodeAsync expects a function",
  );
});

test.each([null, undefined, 1, "failure"])("throw matchers report thrown primitives: %p", async thrown => {
  const message = `Expected error to be instanceof Error; got ${Bun.inspect(thrown)}`;
  expect(() =>
    expect(() => {
      throw thrown;
    }).toThrowWithCode(Error, "ERR_TEST"),
  ).toThrow(message);
  await assertAsyncMatcherFailure(
    `expect(async () => { throw ${JSON.stringify(thrown)}; }).toThrowWithCodeAsync(Error, "ERR_TEST")`,
    message,
  );
});

test("throw matchers accept errors with the expected code", async () => {
  const error = Object.assign(new Error("test failure"), { code: "ERR_TEST" });
  expect(() => {
    throw error;
  }).toThrowWithCode(Error, "ERR_TEST");
  await expect(async () => {
    throw error;
  }).toThrowWithCodeAsync(Error, "ERR_TEST");
});

async function assertAsyncMatcherFailure(expression: string, diagnostic: string) {
  using directory = tempDir("async-matcher-failure", {
    "matcher.test.ts": `
      import ${JSON.stringify(join(import.meta.dir, "../../../harness.ts"))};
      import { expect, test } from "bun:test";
      test("async matcher failure", async () => {
        await ${expression};
      });
    `,
  });
  await using proc = Bun.spawn({
    cmd: [bunExe(), "test", "matcher.test.ts"],
    cwd: String(directory),
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
  expect(stdout.trim()).toBe(`bun test v${Bun.version.replace(/-debug$/, "")} (${Bun.revision.slice(0, 9)})`);
  expect(stderr).toContain(diagnostic);
  expect(stderr).toContain("1 fail");
  expect(exitCode).toBe(1);
}

test("registry user creation returns the response token", async () => {
  const registry = new VerdaccioRegistry();
  const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ token: "registry-token" }));
  try {
    expect(await registry.generateUser("test-user", "test-password")).toBe("registry-token");
    expect(fetchMock).toHaveBeenCalledWith(`http://localhost:${registry.port}/-/user/org.couchdb.user:test-user`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "test-user", password: "test-password", email: "test-user@example.com" }),
    });
  } finally {
    fetchMock.mockRestore();
  }
});

test.each([null, "token", {}, { token: null }, { token: 123 }])(
  "registry user creation rejects invalid token responses: %p",
  async response => {
    const registry = new VerdaccioRegistry();
    const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(Response.json(response));
    try {
      await expect(registry.generateUser("test-user", "test-password")).rejects.toThrow(
        "Failed to create user: response is missing a token",
      );
    } finally {
      fetchMock.mockRestore();
    }
  },
);

test("registry user creation includes HTTP failure status text", async () => {
  const registry = new VerdaccioRegistry();
  const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(null, { status: 403, statusText: "Forbidden" }),
  );
  try {
    await expect(registry.generateUser("test-user", "test-password")).rejects.toThrow(
      "Failed to create user: Forbidden",
    );
  } finally {
    fetchMock.mockRestore();
  }
});
