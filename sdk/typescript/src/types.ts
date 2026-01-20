/**
 * Ritma configuration types
 */

export type PrivacyMode = 'full' | 'redacted' | 'minimal';
export type DeployType = 'standalone' | 'kubernetes' | 'docker' | 'systemd';
export type AlertChannel = 'webhook' | 'email' | 'slack' | 'pagerduty';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type MLModel = 'anomaly' | 'behavior' | 'threat' | 'compliance';
export type ComplianceFramework = 'pipeda' | 'sox' | 'hipaa' | 'pci-dss' | 'gdpr' | 'law25';

export interface NodeConfig {
  id?: string;
  labels?: Record<string, string>;
}

export interface StorageConfig {
  baseDir?: string;
  outDir?: string;
  casEnabled?: boolean;
  retentionDays?: number;
}

export interface CaptureConfig {
  windowSeconds?: number;
  privacyMode?: PrivacyMode;
  watchPaths?: string[];
  watchProcesses?: string[];
  excludePaths?: string[];
}

export interface MLConfig {
  enabled?: boolean;
  threshold?: number;
  models?: MLModel[];
}

export interface AlertChannelConfig {
  type: AlertChannel;
  url?: string;
  email?: string;
  severity?: Severity;
}

export interface AlertConfig {
  enabled?: boolean;
  channels?: AlertChannelConfig[];
}

export interface ComplianceConfig {
  frameworks?: ComplianceFramework[];
  auditLog?: boolean;
}

export interface ResourceConfig {
  memory?: string;
  cpu?: string;
}

export interface DeployConfig {
  type?: DeployType;
  replicas?: number;
  resources?: ResourceConfig;
}

export interface RitmaConfigData {
  version: string;
  namespace: string;
  node?: NodeConfig;
  storage?: StorageConfig;
  capture?: CaptureConfig;
  ml?: MLConfig;
  alerts?: AlertConfig;
  compliance?: ComplianceConfig;
  deploy?: DeployConfig;
}

export interface RitmaStatus {
  active: boolean;
  namespace: string;
}

export interface CaptureResult {
  path: string;
  events: number;
  duration: number;
}

export interface VerifyResult {
  valid: boolean;
  errors?: string[];
}
