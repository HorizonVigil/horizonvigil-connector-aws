import { serve } from '@hono/node-server';
import app from './index';

const port = Number(process.env.PORT) || 8080;
serve({ fetch: (request) => app.fetch(request, process.env), port });
console.log(`listening on :${port}`);
