import { build, emptyDir } from "dnt";

await emptyDir("./npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: false,
  test: true,
  declaration: true,
  scriptModule: "umd",
  alwaysStrict: false,
  importMap: "./import-map.json",
  compilerOptions: {
    lib: ["es2021", "dom"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "ohttp-js",
    version: Deno.args[0],
    description: "Oblivious HTTP Javascript library",
    repository: {
      type: "git",
      url: "git+https://github.com/chris-wood/ohttp-js.git",
    },
    homepage: "https://github.com/chris-wood/ohttp-js#readme",
    license: "MIT",
    main: "./script/mod.js",
    types: "./types/mod.d.ts",
    exports: {
      ".": {
        "import": "./esm/mod.js",
        "require": "./script/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "ohttp",
    ],
    engines: {
      "node": ">=16.0.0",
    },
    author: "Christopher A. Wood <caw@heapingbits.net>",
    bugs: {
      url: "https://github.com/chris-wood/ohttp-js/issues",
    },
  },
});

// post build steps
Deno.copyFileSync("LICENSE", "npm/LICENSE");
Deno.copyFileSync("README.md", "npm/README.md");
