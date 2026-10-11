import {strict as assert} from 'node:assert';
import {readFileSync} from 'node:fs';
const config=JSON.parse(readFileSync(new URL('../vercel.json',import.meta.url),'utf8'));
const route=config.rewrites[0];
assert.equal(route.source,'/api/:path*');
assert.equal(route.destination,'https://agent-trust-firewall-api.onrender.com/api/:path*');
assert(!route.destination.includes('$') && !route.destination.includes('?'));
assert(config.headers.some((h:any)=>h.source==='/api/(.*)' && h.headers.some((v:any)=>v.key==='Cache-Control' && v.value.includes('no-store'))));
console.log('Pinned API route and visitor-response cache checks passed');
