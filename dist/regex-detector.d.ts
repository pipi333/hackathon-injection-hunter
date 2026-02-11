/**
 * Regex-based Injection Pattern Detector
 *
 * Detects common prompt injection patterns including:
 * - Jailbreak attempts (DAN, AIM, etc.)
 * - System prompt overrides
 * - Context manipulation
 * - Roleplay escapes
 * - Chinese injection patterns
 * - Emoji/Unicode manipulation
 * - Base64 encoding attacks
 */
import type { Threat } from './types.js';
export declare class RegexDetector {
    private patterns;
    constructor();
    private initializePatterns;
    scan(input: string): Threat[];
    private deduplicate;
    getPatternCount(): number;
    listCategories(): string[];
}
