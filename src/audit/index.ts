/**
 * AuditLogger - Log every agent action for accountability
 */

import { randomUUID } from 'crypto';

export type StorageType = 'memory' | 'file';

export interface AuditConfig {
  storage: StorageType;
  filePath?: string;
  includeTimestamps?: boolean;
  maxEntries?: number;  // max entries to keep in memory
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  action: string;
  details: Record<string, any>;
  txSignature?: string;
  firewallResult?: {
    allowed: boolean;
    reason?: string;
  };
  sanitizerResult?: {
    threatsDetected: number;
    modified: boolean;
  };
  isolatorResult?: {
    secretsRedacted: number;
  };
}

export interface AuditFilter {
  action?: string;
  fromTimestamp?: number;
  toTimestamp?: number;
  txSignature?: string;
  limit?: number;
}

export class AuditLogger {
  private config: Required<AuditConfig>;
  private entries: Map<string, AuditEntry> = new Map();
  private fs: any = null;

  constructor(config: AuditConfig) {
    this.config = {
      storage: config.storage,
      filePath: config.filePath || './agentguard-audit.json',
      includeTimestamps: config.includeTimestamps ?? true,
      maxEntries: config.maxEntries || 10000
    };

    // Load existing entries if file storage
    if (this.config.storage === 'file') {
      this.loadFromFile();
    }
  }

  private async loadFromFile(): Promise<void> {
    try {
      // Dynamic import for Node.js fs
      if (!this.fs) {
        this.fs = await import('fs').then(m => m.promises);
      }
      
      const data = await this.fs.readFile(this.config.filePath, 'utf-8');
      const entries: AuditEntry[] = JSON.parse(data);
      entries.forEach(e => this.entries.set(e.id, e));
    } catch (err: any) {
      if (err.code !== 'ENOENT') {
        console.error('Failed to load audit log:', err);
      }
    }
  }

  private async saveToFile(): Promise<void> {
    if (this.config.storage !== 'file') return;
    
    try {
      if (!this.fs) {
        this.fs = await import('fs').then(m => m.promises);
      }
      
      const entries = Array.from(this.entries.values());
      await this.fs.writeFile(
        this.config.filePath,
        JSON.stringify(entries, null, 2)
      );
    } catch (err) {
      console.error('Failed to save audit log:', err);
    }
  }

  /**
   * Log an action
   */
  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<string> {
    const id = randomUUID();
    const fullEntry: AuditEntry = {
      id,
      timestamp: this.config.includeTimestamps ? Date.now() : 0,
      ...entry
    };

    // Enforce max entries (remove oldest)
    if (this.entries.size >= this.config.maxEntries) {
      const oldest = Array.from(this.entries.values())
        .sort((a, b) => a.timestamp - b.timestamp)[0];
      if (oldest) {
        this.entries.delete(oldest.id);
      }
    }

    this.entries.set(id, fullEntry);
    
    if (this.config.storage === 'file') {
      await this.saveToFile();
    }

    return id;
  }

  /**
   * Log a transaction check
   */
  async logTransactionCheck(
    action: string,
    details: Record<string, any>,
    firewallResult: { allowed: boolean; reason?: string },
    txSignature?: string
  ): Promise<string> {
    return this.log({
      action,
      details,
      firewallResult,
      txSignature
    });
  }

  /**
   * Log a sanitization
   */
  async logSanitization(
    inputPreview: string,
    threatsDetected: number,
    modified: boolean
  ): Promise<string> {
    return this.log({
      action: 'sanitize',
      details: { inputPreview: inputPreview.slice(0, 100) },
      sanitizerResult: { threatsDetected, modified }
    });
  }

  /**
   * Log a secret redaction
   */
  async logRedaction(
    secretsRedacted: number,
    types: string[]
  ): Promise<string> {
    return this.log({
      action: 'redact',
      details: { types },
      isolatorResult: { secretsRedacted }
    });
  }

  /**
   * Get a specific log entry
   */
  async getLog(id: string): Promise<AuditEntry | null> {
    return this.entries.get(id) || null;
  }

  /**
   * Get logs with optional filtering
   */
  async getLogs(filter?: AuditFilter): Promise<AuditEntry[]> {
    let entries = Array.from(this.entries.values());

    if (filter) {
      if (filter.action) {
        entries = entries.filter(e => e.action === filter.action);
      }
      if (filter.fromTimestamp) {
        entries = entries.filter(e => e.timestamp >= filter.fromTimestamp!);
      }
      if (filter.toTimestamp) {
        entries = entries.filter(e => e.timestamp <= filter.toTimestamp!);
      }
      if (filter.txSignature) {
        entries = entries.filter(e => e.txSignature === filter.txSignature);
      }
      if (filter.limit) {
        entries = entries.slice(0, filter.limit);
      }
    }

    // Sort by timestamp descending (most recent first)
    return entries.sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Get summary statistics
   */
  async getStats(): Promise<{
    totalEntries: number;
    byAction: Record<string, number>;
    blockedTransactions: number;
    threatsDetected: number;
    secretsRedacted: number;
  }> {
    const entries = Array.from(this.entries.values());
    
    const byAction: Record<string, number> = {};
    let blockedTransactions = 0;
    let threatsDetected = 0;
    let secretsRedacted = 0;

    for (const entry of entries) {
      byAction[entry.action] = (byAction[entry.action] || 0) + 1;
      
      if (entry.firewallResult && !entry.firewallResult.allowed) {
        blockedTransactions++;
      }
      if (entry.sanitizerResult) {
        threatsDetected += entry.sanitizerResult.threatsDetected;
      }
      if (entry.isolatorResult) {
        secretsRedacted += entry.isolatorResult.secretsRedacted;
      }
    }

    return {
      totalEntries: entries.length,
      byAction,
      blockedTransactions,
      threatsDetected,
      secretsRedacted
    };
  }

  /**
   * Export all logs as JSON
   */
  async export(): Promise<string> {
    const entries = await this.getLogs();
    const stats = await this.getStats();
    
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      stats,
      entries
    }, null, 2);
  }

  /**
   * Clear all logs
   */
  async clear(): Promise<void> {
    this.entries.clear();
    if (this.config.storage === 'file') {
      await this.saveToFile();
    }
  }
}
