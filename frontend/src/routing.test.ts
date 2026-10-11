import {strict as assert} from 'node:assert';
import {routeFromHash} from './routing.ts';
for(const page of ['Overview','Agents','Threat Intelligence','File Scanner','Attack Lab','Security Events','Policies','Evaluations','Settings','Protected Agents','Runtime Activity','Security Incidents','Security Policies','Security Lab','Integrations','Agent Details']) {
 const alias:Record<string,string>={Agents:'Protected Agents',Policies:'Security Policies','Security Events':'Event Log'};
 assert.equal(routeFromHash('#'+encodeURIComponent(page)),alias[page]||page);
}
assert.equal(routeFromHash(''),'Overview');
assert.equal(routeFromHash('#%'),'Overview');
console.log('Navigation encoding checks passed');

assert.equal(routeFromHash("#missing-page"),"Overview");
