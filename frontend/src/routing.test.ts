import {strict as assert} from 'node:assert';
import {routeFromHash} from './routing.ts';
for(const page of ['Overview','Agents','Threat Intelligence','File Scanner','Attack Lab','Security Events','Policies','Evaluations','Settings']) {
 assert.equal(routeFromHash('#'+encodeURIComponent(page)),page);
}
assert.equal(routeFromHash(''),'Overview');
assert.equal(routeFromHash('#%'),'Overview');
console.log('Navigation encoding checks passed');

assert.equal(routeFromHash("#missing-page"),"Overview");
