/** Portable SDK test target: SDK_RUNTIME is the node_modules directory, or use SCHEDULE_PACKAGE_DIR. */
import { createRequire } from 'node:module';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
export const packagePath = process.env.SCHEDULE_PACKAGE_DIR
    ? resolve(process.env.SCHEDULE_PACKAGE_DIR)
    : process.env.SDK_RUNTIME
        ? resolve(process.env.SDK_RUNTIME, '@deepseek-ai/dsh-schedule')
        : resolve(here, '../patched');
export const sdkModule = relative => import(pathToFileURL(resolve(packagePath, relative)).href);
const sdkRequire = createRequire(resolve(packagePath, 'package.json'));
export const sdkDependency = specifier => import(pathToFileURL(sdkRequire.resolve(specifier)).href);
