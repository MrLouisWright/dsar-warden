export * from './core.js';
import type { Report, Finding } from './core.js';
export declare const RULES: Record<string, { severity: string; title: string }>;
export declare const DEFAULT_FILES: string[];
export interface Source { id: string; name?: string; path: string; format?: 'json' | 'jsonl' | 'ndjson' | 'csv' | 'tsv'; recordsPath?: string; delimiter?: string; match?: string | Record<string, string | string[]>; include?: string[]; exclude?: string[]; redact?: string[]; purpose?: string; category?: string; recipients?: string[]; retention?: string; thirdPartyReviewed?: boolean; }
export interface Manifest { request?: { id?: string; subject?: Record<string, string | string[]>; received?: string; verified?: boolean; extended?: boolean; completed?: boolean; deadlineDays?: number }; sources: Source[]; }
export interface Bundle { schema: string; generatedAt: string; request: Record<string, unknown>; summary: { sources: number; withRecords: number; records: number }; sources: Array<Record<string, unknown> & { id: string; count: number; status: string; records: unknown[] }>; }
export declare function parseCsv(text: string, delimiter?: string): Record<string, string>[];
export declare function loadRecords(file: string, src?: Partial<Source>): unknown[];
export declare function matchesSubject(rec: unknown, match: Record<string, string | string[]>, subject: Record<string, string | string[]>): boolean;
export declare function dueDate(received: string, opts?: { days?: number; months?: number; extended?: boolean }): Date | null;
export declare function assemble(manifest: Manifest, opts?: { baseDir?: string; subject?: Record<string, string | string[]>; now?: Date; warnDays?: number }): { bundle: Bundle; raw: Finding[] };
export declare function writeBundle(bundle: Bundle, outDir: string): string[];
export declare function parseSubject(list?: string[]): Record<string, string | string[]>;
export declare function check(target?: string, opts?: { subject?: Record<string, string | string[]>; out?: string; now?: Date; warnDays?: number; includeBundle?: boolean; toolVersion?: string }, config?: Record<string, unknown>, configFile?: string): Report;
