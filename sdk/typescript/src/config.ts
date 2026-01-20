/**
 * Ritma configuration loader and manager
 */

import * as fs from 'fs';
import * as yaml from 'js-yaml';
import {
  RitmaConfigData,
  NodeConfig,
  StorageConfig,
  CaptureConfig,
  MLConfig,
  AlertConfig,
  ComplianceConfig,
  DeployConfig,
  PrivacyMode,
  DeployType,
} from './types';

export class RitmaConfig {
  version: string;
  namespace: string;
  node: NodeConfig;
  storage: StorageConfig;
  capture: CaptureConfig;
  ml: MLConfig;
  alerts: AlertConfig;
  compliance: ComplianceConfig;
  deploy: DeployConfig;

  constructor(data: RitmaConfigData) {
    this.version = data.version || '1.0';
    this.namespace = data.namespace;
    this.node = data.node || {};
    this.storage = {
      baseDir: '/var/lib/ritma',
      casEnabled: true,
      retentionDays: 90,
      ...data.storage,
    };
    this.capture = {
      windowSeconds: 300,
      privacyMode: 'full' as PrivacyMode,
      watchPaths: [],
      watchProcesses: [],
      excludePaths: [],
      ...data.capture,
    };
    this.ml = {
      enabled: true,
      threshold: 0.7,
      models: ['anomaly', 'behavior'],
      ...data.ml,
    };
    this.alerts = {
      enabled: false,
      channels: [],
      ...data.alerts,
    };
    this.compliance = {
      frameworks: [],
      auditLog: true,
      ...data.compliance,
    };
    this.deploy = {
      type: 'systemd' as DeployType,
      replicas: 1,
      resources: { memory: '256Mi', cpu: '100m' },
      ...data.deploy,
    };
  }

  /**
   * Load configuration from YAML file
   */
  static async fromYaml(path: string): Promise<RitmaConfig> {
    const content = await fs.promises.readFile(path, 'utf-8');
    const data = yaml.load(content) as RitmaConfigData;
    return new RitmaConfig(data);
  }

  /**
   * Load configuration from YAML file (sync)
   */
  static fromYamlSync(path: string): RitmaConfig {
    const content = fs.readFileSync(path, 'utf-8');
    const data = yaml.load(content) as RitmaConfigData;
    return new RitmaConfig(data);
  }

  /**
   * Create configuration from object
   */
  static fromObject(data: RitmaConfigData): RitmaConfig {
    return new RitmaConfig(data);
  }

  /**
   * Convert to plain object
   */
  toObject(): RitmaConfigData {
    return {
      version: this.version,
      namespace: this.namespace,
      node: this.node,
      storage: this.storage,
      capture: this.capture,
      ml: this.ml,
      alerts: this.alerts,
      compliance: this.compliance,
      deploy: this.deploy,
    };
  }

  /**
   * Export to YAML string
   */
  toYaml(): string {
    return yaml.dump(this.toObject(), { noRefs: true, sortKeys: false });
  }

  /**
   * Save to YAML file
   */
  async saveYaml(path: string): Promise<void> {
    await fs.promises.writeFile(path, this.toYaml(), 'utf-8');
  }

  /**
   * Convert to environment variables
   */
  toEnv(): Record<string, string> {
    const env: Record<string, string> = {
      RITMA_NAMESPACE: this.namespace,
      RITMA_BASE_DIR: this.storage.baseDir || '/var/lib/ritma',
      RITMA_CAS_ENABLE: this.storage.casEnabled ? '1' : '0',
      RITMA_OUT_ENABLE: '1',
      RITMA_WINDOW_SECONDS: String(this.capture.windowSeconds || 300),
      RITMA_PRIVACY_MODE: this.capture.privacyMode || 'full',
    };

    if (this.node.id) {
      env.RITMA_NODE_ID = this.node.id;
    }
    if (this.storage.outDir) {
      env.RITMA_OUT_DIR = this.storage.outDir;
    }

    return env;
  }

  /**
   * Validate configuration
   */
  validate(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.namespace) {
      errors.push('namespace is required');
    }

    if (this.capture.windowSeconds && this.capture.windowSeconds < 10) {
      errors.push('capture.windowSeconds must be >= 10');
    }

    if (this.ml.threshold && (this.ml.threshold < 0 || this.ml.threshold > 1)) {
      errors.push('ml.threshold must be between 0 and 1');
    }

    return { valid: errors.length === 0, errors };
  }
}
