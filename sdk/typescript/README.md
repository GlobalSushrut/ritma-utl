# Ritma TypeScript SDK

TypeScript/Node.js SDK for configuring and deploying Ritma forensic security platform.

## Installation

```bash
npm install @ritma/sdk
# or
yarn add @ritma/sdk
```

## Quick Start

### Load and Deploy Configuration

```typescript
import { RitmaConfig, RitmaClient } from '@ritma/sdk';

// Load from YAML
const config = await RitmaConfig.fromYaml('ritma.yaml');

// Deploy
const client = new RitmaClient(config);
await client.deploy();
```

### Create Configuration Programmatically

```typescript
import { RitmaConfig, RitmaClient } from '@ritma/sdk';

const config = RitmaConfig.fromObject({
  version: '1.0',
  namespace: 'my-app-prod',
  capture: {
    windowSeconds: 300,
    privacyMode: 'full',
    watchPaths: ['/etc/passwd', '/var/log/auth.log'],
  },
  ml: {
    enabled: true,
    threshold: 0.7,
    models: ['anomaly', 'behavior'],
  },
  compliance: {
    frameworks: ['pipeda', 'sox'],
  },
});

// Export to YAML
await config.saveYaml('ritma.yaml');

// Deploy
const client = new RitmaClient(config);
await client.deploy();
```

### Generate Kubernetes Manifests

```typescript
import { RitmaConfig, RitmaClient } from '@ritma/sdk';

const config = await RitmaConfig.fromYaml('ritma.yaml');
config.deploy = { type: 'kubernetes', replicas: 3 };

const client = new RitmaClient(config);
const k8sManifest = client.generateK8sManifest();

console.log(k8sManifest);
```

### Generate Docker Compose

```typescript
const config = await RitmaConfig.fromYaml('ritma.yaml');
config.deploy = { type: 'docker' };

const client = new RitmaClient(config);
const compose = client.generateDockerCompose();

console.log(compose);
```

### Capture and Verify

```typescript
import { RitmaConfig, RitmaClient } from '@ritma/sdk';

const config = await RitmaConfig.fromYaml('ritma.yaml');
const client = new RitmaClient(config);

// Capture events for 60 seconds
await client.capture(60, './evidence');

// Verify proofpack
const result = client.verify('./evidence/proofpack');
console.log(`Proofpack valid: ${result.valid}`);
```

## Configuration Reference

See [ritma.example.yaml](../../schemas/ritma.example.yaml) for full configuration options.

## License

Apache 2.0
