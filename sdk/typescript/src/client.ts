/**
 * Ritma client for deployment and management
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawn } from 'child_process';
import { RitmaConfig } from './config';
import { RitmaStatus, CaptureResult, VerifyResult } from './types';

export class RitmaClient {
  private config: RitmaConfig;
  private ritmaBin: string;

  constructor(config: RitmaConfig) {
    this.config = config;
    this.ritmaBin = this.findRitma();
  }

  private findRitma(): string {
    const paths = ['/usr/bin/ritma', '/usr/local/bin/ritma'];
    
    for (const p of paths) {
      if (fs.existsSync(p)) {
        return p;
      }
    }

    try {
      const which = execSync('which ritma', { encoding: 'utf-8' }).trim();
      if (which) return which;
    } catch {}

    throw new Error('ritma binary not found. Install with: sudo apt install ritma');
  }

  /**
   * Deploy Ritma with current configuration
   */
  async deploy(): Promise<boolean> {
    const validation = this.config.validate();
    if (!validation.valid) {
      throw new Error(`Invalid config: ${validation.errors.join(', ')}`);
    }

    const deployType = this.config.deploy.type;

    switch (deployType) {
      case 'systemd':
        return this.deploySystemd();
      case 'kubernetes':
        return this.deployKubernetes();
      case 'docker':
        return this.deployDocker();
      default:
        return this.deployStandalone();
    }
  }

  private async deploySystemd(): Promise<boolean> {
    const configPath = '/etc/ritma/ritma.yaml';
    const envPath = '/etc/ritma/ritma.conf';

    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    await this.config.saveYaml(configPath);

    const env = this.config.toEnv();
    const envContent = Object.entries(env)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    fs.writeFileSync(envPath, envContent);

    execSync('systemctl daemon-reload');
    execSync('systemctl enable ritma-sidecar');
    execSync('systemctl start ritma-sidecar');

    return true;
  }

  private async deployKubernetes(): Promise<boolean> {
    const manifest = this.generateK8sManifest();
    console.log(manifest);
    return true;
  }

  private async deployDocker(): Promise<boolean> {
    const compose = this.generateDockerCompose();
    console.log(compose);
    return true;
  }

  private async deployStandalone(): Promise<boolean> {
    const configPath = path.join(
      this.config.storage.baseDir || '/var/lib/ritma',
      'ritma.yaml'
    );
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    await this.config.saveYaml(configPath);

    const env = this.config.toEnv();
    console.log(`Config written to: ${configPath}`);
    console.log(`Run with: ${Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ')} ritma-sidecar`);
    return true;
  }

  /**
   * Generate Kubernetes manifests
   */
  generateK8sManifest(): string {
    const yamlConfig = this.config.toYaml().split('\n').map(l => '    ' + l).join('\n');
    
    return `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ritma-config
  namespace: ${this.config.namespace}
data:
  ritma.yaml: |
${yamlConfig}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ritma-sidecar
  namespace: ${this.config.namespace}
spec:
  selector:
    matchLabels:
      app: ritma-sidecar
  template:
    metadata:
      labels:
        app: ritma-sidecar
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: ritma-sidecar
        image: ritma/sidecar:latest
        securityContext:
          privileged: true
        resources:
          requests:
            memory: "${this.config.deploy.resources?.memory || '256Mi'}"
            cpu: "${this.config.deploy.resources?.cpu || '100m'}"
        volumeMounts:
        - name: config
          mountPath: /etc/ritma
        - name: data
          mountPath: /var/lib/ritma
        env:
        - name: RITMA_NAMESPACE
          value: "${this.config.namespace}"
      volumes:
      - name: config
        configMap:
          name: ritma-config
      - name: data
        hostPath:
          path: /var/lib/ritma
`;
  }

  /**
   * Generate Docker Compose file
   */
  generateDockerCompose(): string {
    return `version: '3.8'
services:
  ritma-sidecar:
    image: ritma/sidecar:latest
    container_name: ritma-sidecar
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    volumes:
      - ./ritma.yaml:/etc/ritma/ritma.yaml:ro
      - ritma-data:/var/lib/ritma
    environment:
      - RITMA_NAMESPACE=${this.config.namespace}
      - RITMA_BASE_DIR=/var/lib/ritma
      - RITMA_OUT_ENABLE=1

volumes:
  ritma-data:
`;
  }

  /**
   * Get service status
   */
  status(): RitmaStatus {
    try {
      const result = execSync('systemctl is-active ritma-sidecar', { encoding: 'utf-8' });
      return {
        active: result.trim() === 'active',
        namespace: this.config.namespace,
      };
    } catch {
      return { active: false, namespace: this.config.namespace };
    }
  }

  /**
   * Run capture session
   */
  async capture(duration: number = 60, output?: string): Promise<string> {
    const args = ['capture', '--duration', String(duration)];
    if (output) {
      args.push('--output', output);
    }

    return execSync(`${this.ritmaBin} ${args.join(' ')}`, { encoding: 'utf-8' });
  }

  /**
   * Verify proofpack
   */
  verify(proofpackPath: string): VerifyResult {
    try {
      execSync(`${this.ritmaBin} verify ${proofpackPath}`);
      return { valid: true };
    } catch (e: any) {
      return { valid: false, errors: [e.message] };
    }
  }

  /**
   * Export sealed windows
   */
  async exportWindows(output: string, namespace?: string): Promise<string> {
    const args = ['export-window', '--output', output];
    if (namespace) {
      args.push('--namespace', namespace);
    }

    return execSync(`${this.ritmaBin} ${args.join(' ')}`, { encoding: 'utf-8' });
  }
}
