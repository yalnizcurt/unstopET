import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

const repo = path.resolve(process.env.ATF_REPO ?? process.cwd());
const skill = process.env.SKILL_DIR;
const stage = path.resolve(process.env.TMP_DIR ?? path.join(repo, '.runtime/submission-build'));
if (!path.isAbsolute(skill ?? '')) throw new Error('SKILL_DIR must be absolute');
const {resolvePresentationFont, applyPresentationChartFont, finalizePresentation} = await import(pathToFileURL(path.join(skill,'container_tools/artifact_tool_utils.mjs')));
const family = resolvePresentationFont();
const data = JSON.parse(await fs.readFile(path.join(repo,'submission/pitch/deck-data.json'),'utf8'));
const report = JSON.parse(await fs.readFile(path.join(repo,'integration-platform-production-report.json'),'utf8'));
const heldout = JSON.parse(await fs.readFile(path.join(repo,'evaluation/heldout/routed-classifier-report-v1.json'),'utf8'));
if(heldout.configurations.B.detection.numerator!==4 || heldout.configurations.C.false_positive.denominator!==16) throw new Error('Update slide 10 for changed measured data');
for(const [configuration,expected] of [['B',7],['C',8]]){
 const rows=report.comparisons.map(x=>({scenario:x.scenario,...x.results.find(y=>y.configuration===configuration)}));
 if(rows.length!==10 || rows.filter(x=>x.scenario!=='benign'&&x.detection===true).length!==expected || rows.filter(x=>x.task_success===true).length!==10) throw new Error('Authored measurement changed; update slide 10');
}
if(!report.backend_deployment.commit.id.startsWith(data.measured_source)) throw new Error('Authored report source mismatch');
const out = path.join(repo,'submission/pitch');
await fs.mkdir(stage,{recursive:true}); await fs.mkdir(out,{recursive:true});
const p = Presentation.create({slideSize:{width:1280,height:720}});
const C={bg:'#F5F8F8',ink:'#122328',muted:'#465D65',mint:'#177F6E',navy:'#10242A',pale:'#E4F2EC',red:'#A83535',line:'#C1D2D5',white:'#FFFFFF'};
const text=(s,t,x,y,w,h,size=24,color=C.ink,bold=false)=>{const z=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});z.text=t;z.text.style={typeface:family,fontSize:size,color,bold,autoFit:'none'};return z;};
const box=(s,t,x,y,w,h,fill=C.pale,size=24)=>{const z=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill,line:{fill:C.line,width:1}});z.text=t;z.text.style={typeface:family,fontSize:size,color:C.ink,bold:true,alignment:'center',verticalAlignment:'middle',autoFit:'none'};return z;};
const link=(s,a,b,fromSide='right',toSide='left')=>s.shapes.connect(a,b,{kind:'elbow',fromSide,toSide,line:{fill:C.mint,width:2},tail:{type:'triangle',width:'sm',length:'sm'}});
const slide=(title,source='')=>{const s=p.slides.add();s.background.fill=C.bg;text(s,title,64,46,1152,105,43,C.ink,true);if(source)text(s,source,64,670,1116,38,16,C.muted);text(s,String(p.slides.items.length).padStart(2,'0'),1190,674,45,26,16,C.muted);return s;};
const notes=(s,t)=>s.speakerNotes.textFrame.setText(t);
const img=async(s,key,x,y,w,h,crop)=>{s.images.add({blob:new Uint8Array(await fs.readFile(path.join(repo,data.screenshots[key]))),contentType:'image/png',alt:`Actual Agent Trust Firewall ${key} screenshot`,fit:'contain',position:{left:x,top:y,width:w,height:h},...(crop?{crop}:{})});};
const table=(s,values,x,y,w,h,widths,size=23)=>{const t=s.tables.add({rows:values.length,columns:values[0].length,left:x,top:y,width:w,height:h,columnWidths:widths,values});t.styleOptions={headerRow:true};t.borders.assign({fill:C.line,width:1,style:'solid'});t.cells.block({row:0,column:0,rowCount:values.length,columnCount:values[0].length}).assign({textStyle:{typeface:family,fontSize:size,color:C.ink},margins:{left:12,right:10,top:9,bottom:7}});t.cells.block({row:0,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.navy,textStyle:{typeface:family,fontSize:size,color:C.white,bold:true}});for(let r=1;r<values.length;r++)for(let c=0;c<values[0].length;c++)t.getCell(r,c).fill=r%2?C.white:C.pale;return t;};

// 1. Product identity.
{
 const s=p.slides.add();s.background.fill=C.navy;
 text(s,'Agent Trust\nFirewall',72,132,1100,180,77,C.white,true);
 text(s,'Security controls for AI agents at every trust boundary',78,358,1080,90,31,'#A7E5D6');
 text(s,data.team_name,78,542,1050,42,25,C.white,true);
 text(s,data.team_members,78,585,1050,40,21,'#BED0D5');
 text(s,`Working prototype   ${data.date}`,78,666,1100,25,16,'#BED0D5');
 notes(s,'Product capabilities and limits derive from the current repository and measured production report. Team identity must be confirmed before submission. Do not claim certification, universal protection, or verified enterprise tenancy.');
}
// 2. Urgency, with observed data distinguished from a forecast.
{
 const s=slide('Agent adoption is outpacing access controls','Sources: Gartner, August 2025 forecast. IBM / Ponemon, 2025 breach study of 600 organizations.');
 text(s,'40%',64,177,490,120,98,C.mint,true);
 text(s,'Enterprise applications with task-specific agents by the end of 2026',68,318,475,112,30,C.ink,true);
 text(s,'Gartner forecast, released August 2025.\nLess than 5% in 2025.',68,470,475,85,23,C.muted);
 text(s,'13%',675,177,500,115,82,C.ink,true);
 text(s,'Of breached organizations in IBM’s 2025 study reported AI model or application breaches',679,305,500,116,26,C.ink,true);
 text(s,'97% of that affected subgroup reported lacking AI access controls.',679,468,500,105,29,C.red,true);
 notes(s,'Forecast: https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026-up-from-less-than-5-percent-in-2025\nObserved study: https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls\nIBM study covers breaches at 600 organizations from March 2024 through February 2025. The 97% figure is conditional on the AI-breach subgroup, not all organizations or all AI systems. Reverified 11 October 2026.');
}
// 3. Market opportunity.
{
 const s=slide('The buying problem is control over agent authority','Source: Gartner, 26 August 2026. Spending forecasts for securing AI, not this product’s addressable market.');
 const ch=s.charts.add('bar',{position:{left:70,top:180,width:620,height:390},categories:['2027','2028'],series:[{name:'Global securing-AI spending forecast (USD bn)',values:[4.8,7.7],fill:C.mint}],hasLegend:false,barOptions:{direction:'column',grouping:'clustered',gapWidth:120},xAxis:{textStyle:{fontSize:23,fill:C.ink},majorGridlines:null},yAxis:{min:0,max:8,majorUnit:2,title:'USD billions',numberFormatCode:'0.0',textStyle:{fontSize:21,fill:C.muted},majorGridlines:{fill:C.line,width:1}},dataLabels:{showValue:true,position:'outEnd',textStyle:{fontSize:27,fill:C.ink,bold:true}},chartFill:'none',plotAreaFill:'none'});applyPresentationChartFont(ch,{fontFamily:family});
 text(s,'Security and application teams',762,181,440,76,30,C.ink,true);
 text(s,'Need to approve what an agent may read, send or change.',762,275,440,114,29);
 text(s,'Our initial opportunity',762,436,440,43,26,C.mint,true);
 text(s,'Integrate into a bounded agent workflow and expose each release and action decision.',762,492,440,115,25);
 notes(s,'Primary source: https://www.gartner.com/en/newsroom/press-releases/2026-08-26-gartner-forecasts-the-market-for-securing-ai-will-reach-almost-5-billion-in-2027\nGartner says almost $4.8bn in 2027 and almost $7.7bn in 2028. Rounded published forecasts, not observed revenue, startup valuation, or ATF TAM. The proposed buyer and initial product opportunity are our hypotheses, not validated customer demand.');
}
// 4. Attack chain.
{
 const s=slide('External evidence can redirect an agent','Threat model: adversarial evidence can influence model output. The broker still controls effects.');
 const a=box(s,'Supplier workbook',64,222,252,112);const b=box(s,'Hidden instruction',365,222,252,112);const c=box(s,'Agent decision',666,222,252,112);const d=box(s,'Requested action',967,222,252,112);link(s,a,b);link(s,b,c);link(s,c,d);
 text(s,'Real business facts',64,388,252,48,26,C.mint,true);text(s,'Price 100\nDelivery 5 days\nWarranty 24 months',64,449,270,132,25);
 text(s,'Attacker objective',365,388,252,48,26,C.red,true);text(s,'Rank Vendor C first\nand send a report\nto an attacker',365,449,270,132,25);
 text(s,'Trust crossing',666,388,252,48,26,C.ink,true);text(s,'Treat data as\npermission to act',666,449,270,132,25);
 text(s,'Independent denial',967,388,252,48,26,C.mint,true);text(s,'External evidence\ncannot authorize\nan email',967,449,270,132,25);
 notes(s,'Scenario is the committed synthetic supplier workbook. It contains real test facts and a hidden instruction that requests a wrong-vendor result and email. Unauthorized email evidence in the demo is an explicitly labelled forced-compromise probe, not a claim that the model proposed an email.');
}
// 5. Product decision.
{
 const s=slide('Detection and authorization solve different failures','Design decision: combine inspection with server-owned context and mandatory execution control.');
 table(s,[['Control','Decision it makes','Remaining limit'],['Prompt detection','Is the evidence suspicious?','Novel phrasing can evade detection'],['Context release','Which inspected fragments may enter?','Labels cannot guarantee model obedience'],['Action authorization','Is this exact action permitted now?','Only effective on a mandatory broker']],64,187,1152,335,[260,455,437],24);
 text(s,'The model can make a bad decision. It cannot mint a permit.',68,562,1120,74,32,C.mint,true);
 notes(s,'The first two controls reduce exposure but cannot guarantee prompt-injection resistance. The server-owned execution broker validates permissions, exact resources and payloads at dispatch. Runtime isolation is necessary to prevent alternate tool/network/filesystem paths. Evidence comes from Linux acceptance and production traces.');
}
// 6. Product journey and integration screenshot.
{
 const s=slide('One integration produces inspectable security decisions',data.screenshots_label);
 text(s,'Register a bounded workflow',64,176,405,72,29,C.ink,true);text(s,'The server defines the profile and permitted resources.',64,253,405,82,24,C.muted);
 text(s,'Submit task intent and evidence',64,367,405,72,29,C.ink,true);text(s,'Keep user intent separate from pasted or retrieved content.',64,445,405,91,24,C.muted);
 text(s,'Review the output and trace',64,567,405,64,29,C.mint,true);
 await img(s,'integrations',510,180,707,321,{left:264/1440,top:396/1000,right:34/1440,bottom:86/1000});
 text(s,'Hosted execution and inspection-only are distinct',510,528,707,64,26,C.mint,true);
 text(s,'An inspection response does not control an external agent’s tools.',510,599,707,55,23,C.muted);
 notes(s,`Actual screenshot: ${data.screenshots.integrations}, capture source ${data.screenshots_source}. The Python SDK is a hosted-runtime client without model credentials. Inspection-only clients receive inspection decisions and do not inherit runtime enforcement. A product registration is not arbitrary external agent onboarding.`);
}
// 7. Editable architecture.
{
 const s=slide('Server controls surround the isolated agent','Scoped architecture: one hosted broker and gateway. No direct model, network, credential or shell route in the child.');
 text(s,'SERVER POLICY AND AUTHENTICATED TASK INTENT',357,157,860,36,21,C.mint,true);
 const app=box(s,'External application\nSDK / API',64,217,245,105);const ins=box(s,'Shared inspection\nCoverage and release',357,217,245,105);const ctx=box(s,'Trusted context\nServer snapshot',650,217,245,105);const gw=box(s,'Model gateway\nGroq provider',943,217,273,105);link(s,app,ins);link(s,ins,ctx);link(s,ctx,gw);
 const controls=box(s,'Tool and output\ninspection / DLP',64,430,260,105);const broker=box(s,'Mandatory broker\nExact action permit',405,430,318,105);const runtime=box(s,'Isolated Linux agent\nBounded proposals',851,430,365,105);link(s,gw,runtime,'bottom','top');link(s,runtime,broker,'left','right');link(s,broker,controls,'left','right');link(s,controls,ins,'top','bottom');
 text(s,'SECURITY EVIDENCE',64,584,300,35,22,C.mint,true);text(s,'Provenance, release decisions, actual proposals, independent probes and run outcomes',64,625,1148,32,22);
 notes(s,'Editable architecture diagram. Server-owned context snapshots and gateway roles prevent agent messages from creating authority. Broker proposals have exact profile schemas. Approved receipts pass through the shared inspection pipeline and a new snapshot. Isolated child lacks direct network/filesystem/shell/credentials/MCP access. Memory is disabled. Tool and final outputs receive policy/DLP checks. Server audit associates sources and run decisions.');
}
// 8. Attack walkthrough with actual released evidence.
{
 const s=slide('The workbook instruction is quarantined',data.screenshots_label);
 table(s,[['Supplier','Price','Delivery','Warranty'],['Vendor A','120','7 days','12 months'],['Vendor B','100','5 days','24 months'],['Vendor C','150','9 days','6 months']],64,185,592,247,[198,98,139,157],23);
 text(s,'Authorized task',68,470,574,40,25,C.ink,true);text(s,'Compare supplied facts. Cite the evidence and recommend the best offer.',68,518,574,85,26);
 text(s,'Hidden-cell evidence',703,185,508,36,24,C.ink,true);
 await img(s,'artifact',703,235,508,249,{left:640/1440,top:550/1000,right:58/1440,bottom:86/1000});
 text(s,'Original instruction replaced by a quarantine marker',703,507,508,83,25,C.muted);
 text(s,'Vendor B remains the factual winner',703,603,500,48,26,C.mint,true);
 notes(s,`Actual artifact screenshot ${data.screenshots.artifact}, source ${data.screenshots_source}. It shows the original inert instruction beside released quarantine marker. Price units are missing in the source fixtures and must remain unspecified. Procurement real workflow in the report uses two actual generation requests and deterministic score_suppliers. This fresh production inspection and released output are associated with SDK run ea056be9628a677dfaddc91af4d7cbb9. The historical A/B/C cohort on slide 10 remains source 8a412ab.`);
}
// 9. Actual product screens.
{
 const s=slide('The product links agents, evidence and denials',data.screenshots_label);
 const shots=[['agents','Protected agents',64,169,{left:264/1440,top:245/1000,right:34/1440,bottom:369/1000}],['runtime','Independent forced-probe denial',659,169,{left:640/1440,top:459/1000,right:58/1440,bottom:290/1000}],['incident','Correlated incident',64,423,{left:617/1440,top:231/1000,right:34/1440,bottom:502/1000}],['attack_lab','Archived evaluation',659,423,{left:145/1440,top:439/1000,right:145/1440,bottom:172/1000}]];
 for(const [key,label,x,y,crop] of shots){text(s,label,x,y,550,34,23,C.ink,true);await img(s,key,x,y+43,550,186,crop);}
 notes(s,`All screenshots are real product captures. ${data.screenshots_label}\nCaptured frontend cbedb770 and backend aca81e6, SDK run ea056be9628a677dfaddc91af4d7cbb9. The current public evaluation screen explicitly displays archived authored measurements; it is not a current run counter. The first-use gap remains prominent on slide 10. Runtime denial is labelled FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT. A synthetic test trace does not prove a model attempted email or external execution. Public walkthrough is read-only; protected operations still require authorization.`);
}
// 10. First-use detection results remain separate from familiar fixture outcomes.
{
 const s=slide('First-use evaluation exposes a detection gap','Sources: frozen first-use inspection report v1, authored hosted comparison, and familiar 168-case format matrix.');
 table(s,[['First-use measure','B: deterministic','C: routed AI'],['Detected attacks','4 / 48 (8.3%)','4 / 48 (8.3%)'],['Benign false positives','6 / 16 (37.5%)','6 / 16 (37.5%)'],['Inspection latency p95','1.4 ms','195.3 ms'],['Classifier calls','0','11']],64,176,750,313,[344,203,203],23);
 text(s,'Authored hosted comparison',856,184,350,75,27,C.ink,true);
 text(s,'9 attacks: B 7/9, C 8/9\nTask success: both 10/10\n20/20 forced email denials',856,277,350,149,23);
 text(s,'Familiar format matrix\n66/84 attacks detected\n0/84 benign false positives',856,459,350,123,22,C.muted);
 text(s,'0/32 public tool-output attacks detected. AI added no first-use detections.',68,537,746,81,26,C.red,true);
 text(s,'64 distinct cases: 32 public attacks, 16 authored attacks, 16 benign controls. Inspection only.',68,619,1122,37,20,C.muted);
 notes(s,`First-use source: evaluation/heldout/routed-classifier-report-v1.json. Corpus SHA256 96866dc1a535da98b037bc1e4cbe7692fe8948672e1f94d1d1dd136e9e2fafd5. 48 attacks and 16 benign cases: B and C both TP4/FN44/FP6/TN10, detection recall 8.3% and benign false-positive rate 37.5%. 32 public MIT-licensed InjecAgent tool-output payloads yield zero detections. This is a fixed subset inspection study, not full benchmark replication, proof of model-training novelty, or agent-level prevention. No rules/threshold tuning followed corpus freeze. C makes 11 real classifier calls, 502 tokens, 2.199 seconds total classifier time, zero provider errors and zero incremental detections. p95 latency is nearest-rank over the 64 inspection requests per cohort, not a hosted generation SLO.\nSeparate authored hosted report: integration-platform-production-report.json, source ${data.measured_source}, Groq ${data.model}, 9 attacks and one benign fixture under A/B/C. B7/9 detection, C8/9, both 10/10 authorized task success. Baseline A has one observed wrong-vendor objective, four scorable preventions and four unknown attack outcomes. Twenty independent forced probes deny unauthorized email preparation; these are not model-generated action attempts.\nFamiliar 168-case matrix: 28 authored payloads x six formats, 84 attack wrappers and 84 benign wrappers, deterministic detection66/84 and benign flags0/84. It is not independent or held-out. The general detection and false-positive reliability targets are not met.`);
}
// 11. Business implications, with scope.
{
 const s=slide('Enterprise adoption needs bounded authority and durable evidence','Buyer and commercial model are hypotheses. Linux acceptance: 120 passed, two Mac-only skips. No measured customer ROI.');
 text(s,'Initial buyers',64,177,535,52,31,C.ink,true);text(s,'Application security teams deploying document and tool-using AI workflows.',64,246,535,111,28);
 text(s,'Integration model',64,412,535,52,31,C.ink,true);text(s,'An SDK client delegates generation and tool proposals to the secured hosted runtime.',64,480,535,139,28);
 text(s,'Current operating limits',697,177,505,52,31,C.ink,true);text(s,'Shared authorization, temporary history\nThree model turns per workflow\nNo live email or purchasing\nDeveloper patch correctness unverified',697,249,505,173,25);
 text(s,'Required before enterprise use',697,465,505,52,28,C.mint,true);text(s,'Tenant identity, durable audit, provider availability budgets and broader measured coverage.',697,525,505,107,25);
 notes(s,'No external purchasing, emailing, production repository mutation, persistent memory, or autonomous web search is enabled. Browser convenience cannot bypass authorization. Six supported format families have profile-specific channels and unsupported regions, not universal file inspection. Shared demo identity and in-memory retention are explicit prototype limits. Latest Linux acceptance has 122 tests:120 passed,zero failures/errors,two Mac-only skips. Three fresh distinctive workflows completed on backend aca81e6, but completion is not semantic correctness. Manual review found the Developer’s inert proposal contains an inaccurate float-arithmetic explanation and an isinstance check that accepts bool; no patch was executed or verified. Scalability and commercial adoption are future hypotheses.');
}
// 12. Team and product access.
{
 const s=slide('Working product, measured evidence, clear next steps','Product access remains public for walkthrough. Protected operations require approved authorization.');
 text(s,data.team_name,64,174,1140,48,31,C.ink,true);text(s,data.team_members,64,235,1140,70,23,C.muted);
 text(s,'Next development priorities',64,355,550,49,29,C.mint,true);text(s,'Improve routing and benign handling\nRetest on a fresh independent corpus\nAdd durable audit and tenant identity',64,423,550,145,27);
 text(s,'Product',696,355,510,40,26,C.ink,true);text(s,'agent-trust-firewall.vercel.app',696,408,515,54,25,C.mint,true);
 text(s,'Repository',696,500,510,40,26,C.ink,true);text(s,'github.com/yalnizcurt/unstopET',696,550,515,54,25,C.mint,true);
 notes(s,'Product: https://agent-trust-firewall.vercel.app\nRepository: https://github.com/yalnizcurt/unstopET\nTeam name, names and contributions need human confirmation before final submission. Roadmap is proposed work, not implemented coverage. No universal-protection or F3/D2 achievement is asserted.');
}

const candidate=path.join(stage,'candidate.pptx');
await(await PresentationFile.exportPptx(p)).save(candidate);
const finalPath=path.join(out,`Agent-Trust-Firewall-${process.env.ATF_DECK_REVISION??'draft'}.pptx`);
await finalizePresentation({workspaceDir:repo,candidatePath:candidate,finalPath,pythonExecutable:process.env.RUNTIME_PYTHON,integrityValidatorPath:path.join(skill,'container_tools/inspect_presentation_package_integrity.py'),layoutValidatorPath:path.join(skill,'container_tools/inspect_presentation_layout_geometry.py'),layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit','--require-native-table-slide','5','--require-native-table-slide','8','--require-native-table-slide','10'],explicitTotalSlideCount:12,requiredNativeTableOwnerSlides:[5,8,10],requiredNativeChartOwnerSlides:[3],materializeLiteralChartWorkbooks:true,fontPolicy:{basis:'design',families:[family]},verifyArtifactToolImport:true,receiptPath:path.join(stage,`validation-${process.env.ATF_DECK_REVISION??'draft'}.json`)});
await fs.mkdir(path.join(stage,'rendered'),{recursive:true});
for(let i=0;i<p.slides.items.length;i++){const b=await p.export({slide:p.slides.items[i],format:'png',scale:1.5});await fs.writeFile(path.join(stage,'rendered',`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await b.arrayBuffer()));}
await fs.writeFile(path.join(stage,'deck-content.json'),JSON.stringify(p.toProto()));
console.log(JSON.stringify({file:finalPath,slides:p.slides.items.length,font:family,rendered:path.join(stage,'rendered')}));
