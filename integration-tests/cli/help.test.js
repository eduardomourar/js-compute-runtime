import test from 'brittle';
import { getBinPath } from 'get-bin-path'
import { prepareEnvironment } from '@jakechampion/cli-testing-library';
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const __dirname = dirname(fileURLToPath(import.meta.url));

const packageJson = readFileSync(join(__dirname, "../../package.json"), {
    encoding: "utf-8",
});
const version = JSON.parse(packageJson).version;

const cli = await getBinPath()

test('--help should return help on stdout and zero exit code', async function (t) {
    const { execute, cleanup } = await prepareEnvironment();
    t.teardown(async function () {
        await cleanup();
    });
    const { code, stdout, stderr } = await execute(process.execPath, `${cli} --help`);

    t.is(code, 0);
    t.alike(stdout, [
        `js-compute-runtime ${version}`,
        'USAGE:',
        'js-compute-runtime [FLAGS] [OPTIONS] [ARGS]',
        'FLAGS:',
        '-h, --help                                              Prints help information',
        '-V, --version                                           Prints version information',
        'OPTIONS:',
        '--engine-wasm <engine-wasm>                             The JS engine Wasm file path',
        '--enable-experimental-high-resolution-time-methods      Enable experimental high-resolution fastly.now() method',
        'ARGS:',
        "<input>     The input JS script's file path [default: bin/index.js]",
        '<output>    The file path to write the output Wasm module to [default: bin/main.wasm]'
    ])
    t.alike(stderr, [])
});

test('-h should return help on stdout and zero exit code', async function (t) {
    const { execute, cleanup } = await prepareEnvironment();
    t.teardown(async function () {
        await cleanup();
    });
    const { code, stdout, stderr } = await execute(process.execPath, `${cli} -h`);
    
    t.is(code, 0);
    t.alike(stdout, [
        `js-compute-runtime ${version}`,
        'USAGE:',
        'js-compute-runtime [FLAGS] [OPTIONS] [ARGS]',
        'FLAGS:',
        '-h, --help                                              Prints help information',
        '-V, --version                                           Prints version information',
        'OPTIONS:',
        '--engine-wasm <engine-wasm>                             The JS engine Wasm file path',
        '--enable-experimental-high-resolution-time-methods      Enable experimental high-resolution fastly.now() method',
        'ARGS:',
        "<input>     The input JS script's file path [default: bin/index.js]",
        '<output>    The file path to write the output Wasm module to [default: bin/main.wasm]'
    ])
    t.alike(stderr, [])
});
