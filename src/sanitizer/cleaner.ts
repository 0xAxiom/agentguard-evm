/**
 * Text cleaning utilities for prompt sanitization
 * 
 * Handles unicode normalization, character stripping,
 * and safe text transformation
 */

import { UNICODE_PATTERNS, MARKDOWN_PATTERNS } from './patterns';

/**
 * Remove zero-width and invisible characters
 */
export function stripZeroWidth(text: string): string {
  return text.replace(UNICODE_PATTERNS.ZERO_WIDTH, '');
}

/**
 * Remove right-to-left override characters
 * These can be used to visually hide malicious text
 */
export function stripRTLOverride(text: string): string {
  return text.replace(UNICODE_PATTERNS.RTL_OVERRIDE, '');
}

/**
 * Remove control characters (keeping standard whitespace)
 */
export function stripControlChars(text: string): string {
  return text.replace(UNICODE_PATTERNS.CONTROL_CHARS, '');
}

/**
 * Remove private use area characters
 */
export function stripPrivateUse(text: string): string {
  return text.replace(UNICODE_PATTERNS.PRIVATE_USE, '');
}

/**
 * Remove tag characters
 */
export function stripTagChars(text: string): string {
  return text.replace(UNICODE_PATTERNS.TAG_CHARS, '');
}

/**
 * Normalize combining character abuse (excessive diacritics)
 */
export function normalizeCombining(text: string): string {
  return text.replace(UNICODE_PATTERNS.COMBINING_ABUSE, '');
}

/**
 * Strip all dangerous unicode in one pass
 */
export function stripDangerousUnicode(text: string): string {
  let result = text;
  result = stripZeroWidth(result);
  result = stripRTLOverride(result);
  result = stripControlChars(result);
  result = stripPrivateUse(result);
  result = stripTagChars(result);
  result = normalizeCombining(result);
  return result;
}

/**
 * Remove markdown formatting
 */
export function stripMarkdown(text: string): string {
  let result = text;
  
  // Remove code blocks
  result = result.replace(MARKDOWN_PATTERNS.CODE_BLOCKS, '[code block removed]');
  result = result.replace(MARKDOWN_PATTERNS.INLINE_CODE, '');
  
  // Remove images
  result = result.replace(MARKDOWN_PATTERNS.IMAGES, '[image removed]');
  
  // Convert links to plain text (keep the text, remove URL)
  result = result.replace(MARKDOWN_PATTERNS.LINKS, '$1');
  
  // Remove HTML tags
  result = result.replace(MARKDOWN_PATTERNS.HTML_TAGS, '');
  
  // Remove headers (keep text)
  result = result.replace(/^#{1,6}\s+/gm, '');
  
  // Remove horizontal rules
  result = result.replace(MARKDOWN_PATTERNS.HR, '');
  
  // Remove bold/italic markers
  result = result.replace(/\*\*([^*]+)\*\*/g, '$1');
  result = result.replace(/\*([^*]+)\*/g, '$1');
  result = result.replace(/__([^_]+)__/g, '$1');
  result = result.replace(/_([^_]+)_/g, '$1');
  result = result.replace(/~~([^~]+)~~/g, '$1');
  
  return result;
}

/**
 * Escape special characters that could be used for injection
 */
export function escapeSpecialChars(text: string): string {
  // Escape characters commonly used in prompt injection
  return text
    .replace(/\[/g, '［')  // Fullwidth brackets
    .replace(/\]/g, '］')
    .replace(/\{/g, '｛')
    .replace(/\}/g, '｝')
    .replace(/</g, '＜')
    .replace(/>/g, '＞')
    .replace(/\|/g, '｜')
    .replace(/`/g, '\'');
}

/**
 * Normalize whitespace (collapse multiple spaces, normalize line endings)
 */
export function normalizeWhitespace(text: string): string {
  return text
    .replace(/\r\n/g, '\n')     // Normalize line endings
    .replace(/\r/g, '\n')
    .replace(/[ \t]+/g, ' ')     // Collapse horizontal whitespace
    .replace(/\n{3,}/g, '\n\n')  // Max 2 consecutive newlines
    .trim();
}

/**
 * Truncate text to max length with indicator
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) {
    return text;
  }
  return text.slice(0, maxLength - 3) + '...';
}

/**
 * Check if a string looks like Base64
 */
export function looksLikeBase64(text: string): boolean {
  // Must be at least 20 chars and divisible by 4
  if (text.length < 20 || text.length % 4 !== 0) {
    return false;
  }
  
  // Check Base64 character set
  const base64Regex = /^[A-Za-z0-9+/]+=*$/;
  if (!base64Regex.test(text)) {
    return false;
  }
  
  // Try to decode and check if result is printable
  try {
    const decoded = Buffer.from(text, 'base64').toString('utf-8');
    // If decoded text contains control chars, suspicious
    const printableRatio = (decoded.match(/[\x20-\x7E]/g) || []).length / decoded.length;
    return printableRatio > 0.8; // Mostly printable = likely encoded text
  } catch {
    return false;
  }
}

/**
 * Decode and analyze Base64 content
 */
export function decodeBase64(text: string): string | null {
  try {
    return Buffer.from(text, 'base64').toString('utf-8');
  } catch {
    return null;
  }
}

/**
 * Check if text contains EVM address format (0x...)
 */
export function containsEVMAddress(text: string): boolean {
  // EVM addresses are 0x followed by 40 hex chars
  const evmAddressRegex = /\b0x[a-fA-F0-9]{40}\b/;
  return evmAddressRegex.test(text);
}

/**
 * Extract EVM addresses from text
 */
export function extractEVMAddresses(text: string): string[] {
  const regex = /\b0x[a-fA-F0-9]{40}\b/g;
  return text.match(regex) || [];
}

/**
 * Check if text contains private key patterns (various formats)
 */
export function containsPrivateKey(text: string): boolean {
  // 64 hex chars (common private key format)
  const hexKeyRegex = /\b[a-fA-F0-9]{64}\b/;
  // Base64-like private key patterns
  const base64KeyRegex = /\b[A-Za-z0-9+/]{64,88}={0,2}\b/;
  
  return hexKeyRegex.test(text) || base64KeyRegex.test(text);
}

/**
 * Mask sensitive data (addresses, etc.)
 */
export function maskAddress(address: string): string {
  if (address.length < 10) return address;
  return `${address.slice(0, 4)}...${address.slice(-4)}`;
}

/**
 * Replace newlines with visible markers for logging
 */
export function visualizeWhitespace(text: string): string {
  return text
    .replace(/\n/g, '↵\n')
    .replace(/\t/g, '→')
    .replace(/ /g, '·');
}

/**
 * Full clean pipeline with all safety measures
 */
export function fullClean(
  text: string, 
  options: {
    stripMarkdown?: boolean;
    maxLength?: number;
    escapeChars?: boolean;
  } = {}
): string {
  let result = text;
  
  // 1. Strip dangerous unicode
  result = stripDangerousUnicode(result);
  
  // 2. Optionally strip markdown
  if (options.stripMarkdown) {
    result = stripMarkdown(result);
  }
  
  // 3. Normalize whitespace
  result = normalizeWhitespace(result);
  
  // 4. Optionally escape special characters
  if (options.escapeChars) {
    result = escapeSpecialChars(result);
  }
  
  // 5. Truncate if needed
  if (options.maxLength && options.maxLength > 0) {
    result = truncate(result, options.maxLength);
  }
  
  return result;
}
