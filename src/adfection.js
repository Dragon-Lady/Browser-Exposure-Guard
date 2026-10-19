"use strict";
// Saved artifact correlation only; never contacts the listed infrastructure.
const ROUTES = new Map([
 ["noas.mtrtb.com", "/getAd"], ["infinoas.mtrtb.com", "/getAd"],
 ["ppv2.mtrtb.com", "/getAd"], ["pqv2.mtrtb.com", "/getAd"],
 ["events.platc-tester.com", "/cplatform/getAd"],
 ["events.myweb3id.io", "/cplatform/getAd"],
 ["noas.powerium.net", "/getAd"], ["qa-noas.powerium.net", "/getAd"],
]);
const SOURCE = "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/";
function inspectArtifact(file, text) {
 const findings=[], seen=new Set();
 // Normalize JSON's escaped slashes. Do not decode entire encoded URLs, which
 // could turn an unrelated site's query value into a claimed destination.
 for(const match of text.replace(/\\\//g,"/").matchAll(/https?:\/\/[^\s"'<>`\\]+/g)) {
  let url; try {url=new URL(match[0]);} catch {continue;}
  const expected=ROUTES.get(url.hostname.toLowerCase());
  if(!expected || url.pathname!==expected || url.username || url.password) continue;
  const indicator=url.hostname.toLowerCase()+url.pathname;
  if(seen.has(indicator)) continue; seen.add(indicator);
  findings.push({severity:"medium",id:"adfection-saved-route-review",path:file,
   reason:"Saved text references a Controlium ad route documented by Citizen Lab. This is an investigation lead, not evidence of spyware delivery or infection.",
   evidence:indicator,
   guidance:"Preserve the saved artifact and correlate its time and provenance. Do not visit the endpoint. This scanner does not intercept live ads or browser exploits. "+SOURCE});
 }
 return findings;
}
module.exports={inspectArtifact};
