const INVITE=new URLSearchParams(location.hash.slice(1)).get("invite")||new URLSearchParams(location.search).get("invite");
const PROVIDERS=["openai","anthropic","gemini","qwen","deepseek"];
const providerNames={openai:"OpenAI",anthropic:"Claude",gemini:"Gemini",qwen:"Qwen",deepseek:"DeepSeek"};
const labels={
 true:"是",false:"否",uncertain:"不确定",unknown:"未知",partial:"部分成立",yes:"有效",no:"无效",not_applicable:"不适用",high:"高",medium:"中",low:"低",
 user_prompt:"用户提示",web_content:"网页内容",file_content:"文件内容",tool_output:"工具输出",message_email:"消息/邮件",database:"数据库",environment_config:"环境/配置",internal_constant:"内部常量",none:"无",
 command_execution:"命令执行",dynamic_code_execution:"动态代码执行",filesystem_read:"文件读取",filesystem_write:"文件写入",filesystem_delete:"文件删除",browser_control:"浏览器控制",network_access:"网络访问",credential_access:"凭据访问",database_access:"数据库访问",external_tool_invocation:"外部工具调用",other:"其他",
 not_assessed:"未评估",candidate:"候选",confirmed:"确认漏洞",rejected:"排除",
 allowlist:"允许列表",schema_validation:"结构校验",canonicalization:"路径规范化",authorization:"授权检查",user_confirmation:"用户确认",sandbox:"沙箱",escaping:"转义/参数化",least_privilege:"最小权限",destination_restriction:"目标限制",secret_redaction:"敏感信息脱敏"
};
const fields={
 behavior_confirmed:{label:"行为真实",values:["true","false","uncertain"]},agent_relevant:{label:"Agent 相关",values:["true","false","uncertain"]},
 source_type:{label:"输入来源",values:["user_prompt","web_content","file_content","tool_output","message_email","database","environment_config","internal_constant","unknown","none"]},source_external:{label:"来源外部",values:["true","false","unknown"]},
 dependency_confirmed:{label:"依赖成立",values:["true","false","partial","unknown"]},trust_boundary_crossed:{label:"边界跨越",values:["true","false","unknown"]},
 effect_type:{label:"效果类型",values:["command_execution","dynamic_code_execution","filesystem_read","filesystem_write","filesystem_delete","browser_control","network_access","credential_access","database_access","external_tool_invocation","other","none"]},
 guard_present:{label:"存在防护",values:["true","false","unknown"]},guard_effective:{label:"防护有效",values:["yes","no","partial","unknown","not_applicable"]},
 weakness_present:{label:"存在弱点",values:["true","false","uncertain"]},vulnerability_status:{label:"漏洞状态",values:["not_assessed","candidate","confirmed","rejected"]},label_confidence:{label:"标签信心",values:["high","medium","low"]}
};
const guards=["allowlist","schema_validation","canonicalization","authorization","user_confirmation","sandbox","escaping","least_privilege","destination_restriction","secret_redaction","other"];
const $=id=>document.getElementById(id);
let tasks=[],filtered=[],current=null,currentIndex=0,annotation=null,panel=null,displayedSource="",dirty=false,activeModel="openai";

function apiFetch(url,options={}){const headers={...(options.headers||{})};if(INVITE)headers["X-Annotation-Invite"]=INVITE;return fetch(url,{...options,headers});}
function optionHtml(values){return `<option value="">— 人工判断 —</option>${values.map(v=>`<option value="${v}">${labels[v]||v}</option>`).join("")}`;}

async function init(){
  const response=await apiFetch("/api/tasks");if(!response.ok){const e=await response.json();throw new Error(e.error||"邀请链接无效");}
  const data=await response.json();tasks=data.tasks;$("reviewer").textContent=`审核者 ${data.annotator}`;
  renderGuardChecks();updateFilter();const first=tasks.findIndex(t=>t.status!=="completed");await openTask(first<0?0:first);
  const key=`asb_model_audit_intro_${INVITE||data.annotator}`;if(!localStorage.getItem(key))$("intro").showModal();
  $("startReview").onclick=()=>{localStorage.setItem(key,"true");$("intro").close();};
}

function renderGuardChecks(){const box=$("guardChecks");box.innerHTML=guards.map(v=>`<label class="check"><input type="checkbox" name="guard_types" value="${v}"><span>${labels[v]||v}</span></label>`).join("");box.addEventListener("input",()=>dirty=true);}
function updateFilter(){const q=$("search").value.trim().toLowerCase(),mode=$("filter").value;filtered=tasks.map((t,i)=>({...t,_index:i})).filter(t=>{const text=`${t.task_id} ${t.repository} ${t.file} ${t.candidate_behavior}`.toLowerCase();const modeOk=mode==="all"||(mode==="HIGH"?t.priority==="HIGH":t.status===mode);return(!q||text.includes(q))&&modeOk;});renderList();updateProgress();}
function renderList(){const box=$("taskList");box.textContent="";for(const t of filtered){const b=document.createElement("button");b.className=`task-item ${t.status} ${current?.task_id===t.task_id?"active":""}`;b.innerHTML='<i class="dot"></i><div><strong></strong><span></span><small></small></div>';b.querySelector("strong").textContent=`${t.task_id} · ${labels[t.candidate_behavior]||t.candidate_behavior}`;b.querySelector("span").textContent=`${t.priority} · 分歧 ${t.disagreement_score} · ${t.repository}`;b.querySelector("small").textContent=t.file;b.onclick=()=>requestOpen(t._index);box.appendChild(b);}}
function updateProgress(){const done=tasks.filter(t=>t.status==="completed").length;$("progressText").textContent=`${done} / ${tasks.length}`;$("progressBar").style.width=`${done/tasks.length*100}%`;}
async function requestOpen(index){if(dirty&&!confirm("当前修改尚未保存，确定离开吗？"))return;await openTask(index);}

async function openTask(index){
  currentIndex=Math.max(0,Math.min(tasks.length-1,index));const id=tasks[currentIndex].task_id;const response=await apiFetch(`/api/task?id=${encodeURIComponent(id)}`);const data=await response.json();
  current=data.task;annotation=data.annotation;panel=data.panel;displayedSource=current.source_context;dirty=false;activeModel="openai";
  $("taskId").textContent=`${current.task_id} · ${current.candidate_id}`;$("candidateBehavior").textContent=labels[current.candidate_behavior]||current.candidate_behavior;$("taskMeta").textContent=`${current.repository} / ${current.file} · frozen ${current.git_commit.slice(0,12)}`;
  $("priority").className=`priority ${panel.priority}`;$("priority").textContent=`${panel.priority} · ${panel.disagreement_score}`;$("disagreementText").textContent=`分歧字段：${panel.disagreement_fields.map(f=>fields[f]?.label||f).join("、")||"无"}`;
  renderCode();renderVoteMatrix();fillExtras();renderModelTabs();setStatus(annotation._status||"draft");renderList();$("errors").classList.add("hidden");
  $("loadFull").classList.toggle("hidden",!current.context_truncated);$("loadFull").textContent="加载冻结完整文件";$("prev").disabled=currentIndex===0;window.scrollTo({top:0,behavior:"smooth"});
}

function renderCode(){const code=$("sourceCode").querySelector("code"),evidence=new Set(current.evidence_lines);code.textContent="";for(const line of displayedSource.split("\n")){const span=document.createElement("span"),match=line.match(/^\s*(\d+)\s+\|/);span.className=`code-line ${match&&evidence.has(Number(match[1]))?"evidence":""}`;span.textContent=line||" ";code.appendChild(span);}}

function renderVoteMatrix(){
  const box=$("voteMatrix");box.textContent="";const header=document.createElement("div");header.className="vote-row header";header.innerHTML=`<div class="vote-cell">字段</div>${PROVIDERS.map(p=>`<div class="vote-cell">${providerNames[p]}</div>`).join("")}<div class="vote-cell">人工最终值</div>`;box.appendChild(header);
  for(const [name,cfg] of Object.entries(fields)){const vote=panel.votes[name],row=document.createElement("div");row.className="vote-row";const field=document.createElement("div");field.className="vote-cell vote-field";field.textContent=cfg.label;row.appendChild(field);
    for(const provider of PROVIDERS){const value=vote.by_provider[provider],cell=document.createElement("div");cell.className=`vote-cell ${vote.top_vote_count<5?"disagree":""}`;const chip=document.createElement("span");chip.className=`chip ${!vote.tie&&value===vote.plurality_label?"majority":""} ${vote.tie&&vote.counts[value]===vote.top_vote_count?"tie":""}`;chip.textContent=labels[value]||value;cell.appendChild(chip);row.appendChild(cell);}
    const finalCell=document.createElement("div");finalCell.className="vote-cell";const select=document.createElement("select");select.className="final-select";select.name=name;select.innerHTML=optionHtml(cfg.values);select.value=annotation[name]??"";select.onchange=()=>{dirty=true;applyRules();updateOverrideStyles();};finalCell.appendChild(select);row.appendChild(finalCell);box.appendChild(row);}
  updateOverrideStyles();
}

function updateOverrideStyles(){for(const name of Object.keys(fields)){const select=document.querySelector(`select[name="${name}"]`),vote=panel.votes[name];select.classList.toggle("override",!!select.value&&!vote.tie&&select.value!==vote.plurality_label);}}
function choose(name,value){const e=document.querySelector(`select[name="${name}"]`);if(e)e.value=value??"";}
function applyRules(){if(document.querySelector('select[name="source_type"]').value==="none")choose("source_external","false");if(document.querySelector('select[name="dependency_confirmed"]').value==="false")choose("trust_boundary_crossed","false");if(document.querySelector('select[name="guard_present"]').value==="false"){document.querySelectorAll('[name="guard_types"]').forEach(x=>x.checked=false);choose("guard_effective","not_applicable");}}

function fillExtras(){document.querySelectorAll('[name="guard_types"]').forEach(x=>x.checked=(annotation.guard_types||[]).includes(x.value));$("effectTarget").value=annotation.effect_target||"";$("rationale").value=annotation.rationale||"";$("auditNote").value=annotation.audit_note||"";for(const id of ["effectTarget","rationale","auditNote"]){$(id).oninput=()=>dirty=true;}}
function renderModelTabs(){const tabs=$("modelTabs");tabs.textContent="";for(const provider of PROVIDERS){const b=document.createElement("button");b.className=`model-tab ${provider===activeModel?"active":""}`;b.textContent=providerNames[provider];b.onclick=()=>{activeModel=provider;renderModelTabs();};tabs.appendChild(b);}renderModelDetail();}
function renderModelDetail(){const value=panel.annotations[activeModel],box=$("modelDetail");box.textContent="";const dl=document.createElement("dl");const pairs=[["行为",value.behavior_confirmed],["Agent相关",value.agent_relevant],["来源",value.source_type],["依赖",value.dependency_confirmed],["边界",value.trust_boundary_crossed],["效果",value.effect_type],["效果目标",value.effect_target],["防护",`${value.guard_present} / ${(value.guard_types||[]).join(", ")} / ${value.guard_effective}`],["弱点",value.weakness_present],["漏洞",value.vulnerability_status],["信心",value.label_confidence],["证据行",(value.evidence_line_numbers||[]).join(", ")]];for(const [k,v] of pairs){const dt=document.createElement("dt"),dd=document.createElement("dd");dt.textContent=k;dd.textContent=labels[v]||v||"—";dl.append(dt,dd);}box.appendChild(dl);const r=document.createElement("div");r.className="model-rationale";r.textContent=value.rationale||"无理由";box.appendChild(r);if(value.missing_context){const m=document.createElement("div");m.className="model-rationale";m.textContent=`缺失上下文：${value.missing_context}`;box.appendChild(m);}}

function collect(){const out={...annotation,task_id:current.task_id,candidate_id:current.candidate_id};for(const name of Object.keys(fields))out[name]=document.querySelector(`select[name="${name}"]`).value||null;out.guard_types=[...document.querySelectorAll('[name="guard_types"]:checked')].map(x=>x.value);out.effect_target=$("effectTarget").value.trim();out.rationale=$("rationale").value.trim();out.audit_note=$("auditNote").value.trim();return out;}
async function save(complete){$("errors").classList.add("hidden");const value=collect();const response=await apiFetch("/api/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({task_id:current.task_id,annotation:value,complete})});const result=await response.json();if(!result.ok){showErrors(result.errors||["保存失败"]);return false;}annotation={...value,_status:result.status};dirty=false;tasks[currentIndex].status=result.status;setStatus(result.status);updateFilter();return true;}
function showErrors(errors){const box=$("errors");box.textContent="";const title=document.createElement("strong");title.textContent="请修正以下问题：";const ul=document.createElement("ul");for(const error of errors){const li=document.createElement("li");li.textContent=error;ul.appendChild(li);}box.append(title,ul);box.classList.remove("hidden");box.scrollIntoView({behavior:"smooth",block:"center"});}
function setStatus(status){const e=$("saveState");e.className=`status ${status}`;e.textContent=status==="completed"?"已完成":"未完成/草稿";}
async function nextIncomplete(){for(let offset=1;offset<=tasks.length;offset++){const i=(currentIndex+offset)%tasks.length;if(tasks[i].status!=="completed"){await openTask(i);return;}}alert("150 条模型审核均已完成。");}

$("search").addEventListener("input",updateFilter);$("filter").addEventListener("change",updateFilter);$("prev").onclick=()=>requestOpen(currentIndex-1);$("saveDraft").onclick=()=>save(false);$("complete").onclick=async()=>{if(await save(true))await nextIncomplete();};
$("adoptPlurality").onclick=()=>{for(const name of Object.keys(fields)){const vote=panel.votes[name];if(!vote.tie&&vote.plurality_label)choose(name,vote.plurality_label);}applyRules();updateOverrideStyles();dirty=true;};
$("loadFull").onclick=async()=>{const b=$("loadFull");b.disabled=true;b.textContent="正在读取…";try{const response=await apiFetch(`/api/full-source?id=${encodeURIComponent(current.task_id)}`),data=await response.json();if(!response.ok)throw new Error(data.error||"读取失败");displayedSource=data.source_context;renderCode();b.textContent="已加载完整文件";}catch(error){showErrors([`完整文件读取失败：${error}`]);b.textContent="重试加载完整文件";}finally{b.disabled=false;}};
document.addEventListener("keydown",async e=>{if(e.ctrlKey&&e.key.toLowerCase()==="s"){e.preventDefault();await save(false);}if(e.ctrlKey&&e.key==="Enter"){e.preventDefault();if(await save(true))await nextIncomplete();}});window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
init().catch(error=>{document.body.innerHTML="";const pre=document.createElement("pre");pre.textContent=`审核界面加载失败：${error}`;document.body.appendChild(pre);});
