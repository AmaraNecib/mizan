import assert from "node:assert/strict";
import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const temp = mkdtempSync(join(tmpdir(), "mizan-59-packed-"));
const run = (command, args, cwd = temp) => execFileSync(command, args, { cwd, encoding: "utf8", stdio: "pipe" });
const packed = JSON.parse(execSync(`npm pack --ignore-scripts --json --pack-destination "${temp}"`, { cwd: join(root, "packages/core"), encoding: "utf8" }));
const destination = join(temp, "node_modules/@mizan/core");
mkdirSync(destination, { recursive: true });
run("tar", ["-xzf", packed[0].filename, "-C", "node_modules/@mizan/core", "--strip-components=1"]);
copyFileSync(join(root, "packages/core/__tests__/fixtures/role-admin-consumer.mjs"), join(temp, "consumer.mjs"));
console.log(run(process.execPath, ["consumer.mjs"]));
writeFileSync(join(temp, "consumer.mts"), `
import { evaluate, type EffectiveFact } from "@mizan/core";
import { expandRoles, type RoleDefinition, type RoleAssignment } from "@mizan/core/normalization";
const roles: readonly RoleDefinition[] = [{ name: "writer", permissions: [{ permission: "records.edit", effect: "grant" }] }];
const links: readonly RoleAssignment[] = [{ roleName: "writer", scope: { organization: "north" } }];
const facts: readonly EffectiveFact[] = expandRoles(roles, links).facts;
evaluate({ action: "records.edit", at: 0, snapshot: { facts, knownActions: ["records.edit"] } });
// @ts-expect-error Role identity is required.
expandRoles(roles, [{ name: "writer" }]);
// @ts-expect-error Unsupported schedules are excluded.
expandRoles(roles, [{ roleName: "writer", schedule: {} }]);
// @ts-expect-error Effective fact effects remain closed.
expandRoles([], [], [{ permission: "records.edit", effect: "allow" }]);
`);
run(process.execPath, [resolve(root, "node_modules/typescript/bin/tsc"), "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", "consumer.mts"]);
const metadata = JSON.parse(readFileSync(join(destination, "package.json"), "utf8"));
assert.equal(metadata.dependencies, undefined);
console.log(`Packed standalone runtime and public types passed. Consumer: ${temp}`);
console.log(`Archive: ${join(temp, packed[0].filename)}. npm integrity: ${packed[0].integrity}`);
