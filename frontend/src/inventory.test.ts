import assert from 'node:assert/strict';
import {childInventory} from './inventory.ts';
const rows=childInventory([{id:'left',filename:'left.zip',status:'PARTIAL',children:[{id:'a',filename:'README.md',status:'COMPLETE'}]},{id:'right',filename:'right.zip',status:'PARTIAL',children:[{id:'b',filename:'README.md',status:'UNSUPPORTED'}]}]);
assert.deepEqual(rows.filter(r=>r.filename==='README.md').map(r=>[r.path,r.status]),[['left.zip / README.md','COMPLETE'],['right.zip / README.md','UNSUPPORTED']]);
assert.deepEqual(childInventory([]),[]);
console.log('Nested inventory provenance checks passed');
