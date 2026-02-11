/**
 * Known prompt injection patterns for detection
 * 
 * These patterns are commonly used to manipulate LLM behavior
 * through malicious on-chain data (token metadata, NFT descriptions, memos)
 */

export interface InjectionPattern {
  name: string;
  pattern: RegExp;
  severity: 'low' | 'medium' | 'high';
  description: string;
}

/**
 * Instruction override patterns - attempts to hijack the LLM
 */
export const INSTRUCTION_OVERRIDE_PATTERNS: InjectionPattern[] = [
  {
    name: 'ignore_previous',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/gi,
    severity: 'high',
    description: 'Attempts to override previous instructions'
  },
  {
    name: 'disregard_instructions',
    pattern: /disregard\s+(all\s+)?(previous|prior|your|the)\s+(instructions?|rules?|guidelines?)/gi,
    severity: 'high',
    description: 'Attempts to disregard safety guidelines'
  },
  {
    name: 'forget_everything',
    pattern: /forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told)/gi,
    severity: 'high',
    description: 'Attempts to reset LLM context'
  },
  {
    name: 'new_task',
    pattern: /\b(new\s+task|new\s+instruction|instead\s+do|actually\s+do|real\s+task)\s*:/gi,
    severity: 'high',
    description: 'Attempts to inject new task'
  },
  {
    name: 'you_are_now',
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|the)/gi,
    severity: 'medium',
    description: 'Attempts to change LLM persona'
  },
  {
    name: 'pretend_you_are',
    pattern: /(pretend|act\s+like|imagine)\s+(you\s+are|you're|to\s+be)/gi,
    severity: 'medium',
    description: 'Attempts to roleplay override'
  },
  {
    name: 'system_prompt_override',
    pattern: /\[?\s*(system|assistant|user)\s*[:\]]\s*.{0,20}(ignore|forget|override)/gi,
    severity: 'high',
    description: 'Attempts to inject system-level commands'
  },
  {
    name: 'jailbreak_dan',
    pattern: /\b(DAN|do\s+anything\s+now|jailbreak|bypass\s+restrictions?)\b/gi,
    severity: 'high',
    description: 'Known jailbreak technique'
  }
];

/**
 * System prompt extraction attempts
 */
export const PROMPT_LEAKAGE_PATTERNS: InjectionPattern[] = [
  {
    name: 'repeat_instructions',
    pattern: /(repeat|print|show|display|reveal|output)\s+(your\s+)?(system\s+)?(prompt|instructions?|guidelines?)/gi,
    severity: 'medium',
    description: 'Attempts to extract system prompt'
  },
  {
    name: 'what_are_instructions',
    pattern: /what\s+(are|were)\s+(your|the)\s+(original\s+)?(instructions?|prompt|guidelines?|rules?)/gi,
    severity: 'medium',
    description: 'Probing for system prompt'
  },
  {
    name: 'beginning_of_conversation',
    pattern: /(beginning|start|first)\s+(of\s+)?(the\s+)?(conversation|chat|context|prompt)/gi,
    severity: 'low',
    description: 'Probing for context window'
  }
];

/**
 * Solana/Crypto specific injection attempts
 */
export const CRYPTO_INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: 'transfer_all',
    pattern: /(transfer|send|move)\s+(all|entire|whole|every)\s*(sol|tokens?|funds?|balance|crypto)/gi,
    severity: 'high',
    description: 'Attempts to drain wallet'
  },
  {
    name: 'urgent_transfer',
    pattern: /(urgent(ly)?|immediate(ly)?|quick(ly)?|now|asap)\s+(transfer|send|move)/gi,
    severity: 'high',
    description: 'Social engineering urgency'
  },
  {
    name: 'hidden_recipient',
    pattern: /to\s+(this|the\s+following)\s+(address|wallet|account)\s*[:=]?\s*[A-HJ-NP-Za-km-z1-9]{32,44}/gi,
    severity: 'high',
    description: 'Embedded wallet address for theft'
  },
  {
    name: 'approve_unlimited',
    pattern: /(approve|authorize)\s+(unlimited|infinite|max|maximum)\s*(spending|amount|allowance)/gi,
    severity: 'high',
    description: 'Unlimited approval attack'
  },
  {
    name: 'sign_transaction',
    pattern: /(sign|execute|confirm)\s+(this\s+)?(transaction|tx|transfer)\s+(immediately|now|without)/gi,
    severity: 'high',
    description: 'Forced transaction signing'
  }
];

/**
 * Dangerous Unicode sequences
 */
export const UNICODE_PATTERNS = {
  // Zero-width characters (invisible text injection)
  ZERO_WIDTH: /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/g,
  
  // Right-to-left override (text direction manipulation)
  RTL_OVERRIDE: /[\u202A-\u202E\u2066-\u2069]/g,
  
  // Homoglyph confusables (lookalike characters)
  CYRILLIC_CONFUSABLES: /[\u0400-\u04FF]/g, // Cyrillic block
  
  // Tag characters (hidden metadata) 
  TAG_CHARS: /[\u{E0000}-\u{E007F}]/gu,
  
  // Variation selectors
  VARIATION_SELECTORS: /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu,
  
  // Control characters (except common whitespace)
  CONTROL_CHARS: /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,
  
  // Private use area (can hide arbitrary data)
  PRIVATE_USE: /[\uE000-\uF8FF]/g,
  
  // Combining characters abuse (excessive stacking)
  COMBINING_ABUSE: /([\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]){3,}/g
};

/**
 * Encoding-based injection attempts
 */
export const ENCODING_PATTERNS: InjectionPattern[] = [
  {
    name: 'base64_block',
    // Matches base64-looking strings (min 20 chars to avoid false positives)
    pattern: /(?:[A-Za-z0-9+\/]{4}){5,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g,
    severity: 'medium',
    description: 'Potential base64 encoded payload'
  },
  {
    name: 'hex_encoded',
    // Hex strings with 0x prefix (potential encoded instructions)
    pattern: /0x[0-9a-fA-F]{40,}/g,
    severity: 'low',
    description: 'Long hex string (may contain encoded data)'
  },
  {
    name: 'url_encoded',
    // Heavy URL encoding (>30% encoded chars suggests obfuscation)
    pattern: /(%[0-9A-Fa-f]{2}){10,}/g,
    severity: 'medium',
    description: 'Excessive URL encoding'
  }
];

/**
 * All patterns combined for easy iteration
 */
export const ALL_INJECTION_PATTERNS: InjectionPattern[] = [
  ...INSTRUCTION_OVERRIDE_PATTERNS,
  ...PROMPT_LEAKAGE_PATTERNS,
  ...CRYPTO_INJECTION_PATTERNS,
  ...ENCODING_PATTERNS
];

/**
 * Markdown/formatting that could be used for injection
 */
export const MARKDOWN_PATTERNS = {
  // Code blocks (can hide instructions)
  CODE_BLOCKS: /```[\s\S]*?```/g,
  INLINE_CODE: /`[^`]+`/g,
  
  // Links (can contain malicious URLs)
  LINKS: /\[([^\]]+)\]\(([^)]+)\)/g,
  
  // Images (can be used for pixel tracking)
  IMAGES: /!\[([^\]]*)\]\(([^)]+)\)/g,
  
  // HTML tags (shouldn't be in clean text)
  HTML_TAGS: /<[^>]+>/g,
  
  // Headers (can be used to structure injected prompts)
  HEADERS: /^#{1,6}\s+.+$/gm,
  
  // Horizontal rules (section breaks for injection)
  HR: /^[-*_]{3,}$/gm
};

/**
 * Suspicious string patterns that may indicate injection
 */
export const SUSPICIOUS_STRINGS = [
  '```system',
  '```assistant',
  '```user',
  '<|im_start|>',
  '<|im_end|>',
  '<|system|>',
  '<|user|>',
  '<|assistant|>',
  '[INST]',
  '[/INST]',
  '<<SYS>>',
  '<</SYS>>',
  'Human:',
  'Assistant:',
  '### Instruction:',
  '### Response:'
];
