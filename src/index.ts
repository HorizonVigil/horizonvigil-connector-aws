import { createApp, okJson } from '@cloudops360/shared-lib';

const app = createApp();

app.get('/', (c) => okJson({ service: 'cloudops-connector-aws', status: 'skeleton' }));

export default app;
