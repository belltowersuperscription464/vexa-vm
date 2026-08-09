import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const packageRoot = join(projectRoot, "node_modules", "@novnc", "novnc");
const destination = join(projectRoot, "static", "vendor", "novnc");
const coreDestination = join(destination, "core");

await mkdir(coreDestination, { recursive: true });
await build({
  stdin: {
    contents: `
      import * as noVncPackage from "./node_modules/@novnc/novnc/lib/rfb.js";
      const packageDefault = noVncPackage.default ?? noVncPackage;
      const RFB = packageDefault.default ?? packageDefault;
      export default RFB;
    `,
    resolveDir: projectRoot,
    sourcefile: "vexa-novnc-entry.js",
  },
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2020"],
  outfile: join(coreDestination, "rfb.js"),
  minify: true,
  legalComments: "eof",
});
await copyFile(join(packageRoot, "LICENSE.txt"), join(destination, "LICENSE.txt"));
