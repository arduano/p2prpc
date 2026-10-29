import type { Buffer } from 'node:buffer';

export interface PackageArchive {
  readonly artifact: string;
  readonly compressed: Buffer;
  readonly files: ReadonlyMap<string, { readonly content: Buffer; readonly mode: number; readonly size: number }>;
}
export function invariant(condition: unknown, message: string): asserts condition;
export function packageArtifactArgument(position?: number): string;
export function packageInstallSourceArgument(position?: number): string;
export function temporaryDirectory(label: string): Promise<string>;
export function run(command: string, args: readonly string[], options?: { readonly cwd?: string; readonly env?: NodeJS.ProcessEnv }): Promise<void>;
export function runAndCapture(command: string, args: readonly string[], options?: { readonly cwd?: string; readonly env?: NodeJS.ProcessEnv }): Promise<string>;
export function readPackageArchive(artifact: string): Promise<PackageArchive>;
export function writeExtractedPackage(archive: PackageArchive, destination: string): Promise<void>;
