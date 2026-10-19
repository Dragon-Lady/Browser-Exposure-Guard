"use strict";
const {test}=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {inspectArtifact}=require('../src/adfection');
const {scanTarget}=require('../src/scanner');
const routes=['noas.mtrtb.com/getAd','infinoas.mtrtb.com/getAd','ppv2.mtrtb.com/getAd','pqv2.mtrtb.com/getAd','events.platc-tester.com/cplatform/getAd','events.myweb3id.io/cplatform/getAd','noas.powerium.net/getAd','qa-noas.powerium.net/getAd'];
for(const route of routes) test('saved route '+route,()=>{
 const text=JSON.stringify({url:'https://'+route+'?id=PRIVATE-CANARY'});
 const hits=inspectArtifact('saved.har',text);
 assert.equal(hits.length,1);assert.equal(hits[0].severity,'medium');
 assert(!JSON.stringify(hits).includes('PRIVATE-CANARY'));
 assert.match(hits[0].reason,/not evidence/);
 assert.equal(inspectArtifact('saved.har',text.replace(/\//g,'\\/')).length,1);
});
for(const url of ['https://noas.mtrtb.com.example.invalid/getAd','https://example.invalid/noas.mtrtb.com/getAd','https://noas.mtrtb.com/ordinary','https://noas.mtrtb.com/getAdSomething','https://example.invalid/?next=https%3A%2F%2Fnoas.mtrtb.com%2FgetAd','https://noas.mtrtb.com@ordinary.invalid/getAd','https://ordinary.invalid@noas.mtrtb.com/getAd'])
 test('route boundary '+url,()=>assert.deepEqual(inspectArtifact('saved.har',url),[]));
test('real saved HAR scan emits review without query contents',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'adfection-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.writeFileSync(path.join(root,'saved.har'),JSON.stringify({log:{entries:[{request:{url:'https://noas.mtrtb.com/getAd?token=PRIVATE-CANARY'}}]}}));
 const report=scanTarget(root),hit=report.findings.find(f=>f.id==='adfection-saved-route-review');
 assert(hit);assert(!JSON.stringify(hit).includes('PRIVATE-CANARY'));
});

test('JSON Unicode slash escapes and DNS trailing dot retain exact route scope',()=>{
 for(const suffix of ['?id=PRIVATE-CANARY','#PRIVATE-CANARY','']) {
  const url='https://noas.mtrtb.com./getAd'+suffix;
  for(const text of [url,url.replace(/\//g,'\\u002f'),url.replace(/\//g,'\\u002F')]) {
   const hits=inspectArtifact('saved.har',text);
   assert.equal(hits.length,1);assert.equal(hits[0].evidence,'noas.mtrtb.com/getAd');
   assert(!JSON.stringify(hits).includes('PRIVATE-CANARY'));
  }
 }
 for(const url of ['https://noas.mtrtb.com/getAd/','https://noas.mtrtb.com/GETAD','https://noas.mtrtb.com../getAd','https://noas.mtrtb.com.example.invalid/getAd'])
  assert.deepEqual(inspectArtifact('saved.har',url.replace(/\//g,'\\u002f')),[]);
});
