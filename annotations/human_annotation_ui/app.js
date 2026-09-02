const PROVIDER_FREE_NOTICE = "本界面不展示任何模型投票或理由。";
const INVITE = new URLSearchParams(location.hash.slice(1)).get("invite") || new URLSearchParams(location.search).get("invite");
function apiFetch(url, options={}){
  const headers={...(options.headers||{})};
  if(INVITE)headers["X-Annotation-Invite"]=INVITE;
  return fetch(url,{...options,headers});
}
const labels = {
  true:"是", false:"否", uncertain:"不确定", unknown:"未知", partial:"部分成立",
  yes:"有效", no:"无效", not_applicable:"不适用", high:"高", medium:"中", low:"低",
  user_prompt:"用户提示", web_content:"网页内容", file_content:"文件内容", tool_output:"工具输出",
  message_email:"消息/邮件", database:"数据库", environment_config:"环境/配置", internal_constant:"内部常量",
  none:"无", command_execution:"命令执行", dynamic_code_execution:"动态代码执行",
  filesystem_read:"文件读取", filesystem_write:"文件写入", filesystem_delete:"文件删除",
  browser_control:"浏览器控制", network_access:"网络访问", credential_access:"凭据访问",
  database_access:"数据库访问", external_tool_invocation:"外部工具调用", other:"其他",
  allowlist:"允许列表", schema_validation:"结构校验", canonicalization:"路径规范化", authorization:"授权检查",
  user_confirmation:"用户确认", sandbox:"沙箱", escaping:"转义/参数化", least_privilege:"最小权限",
  destination_restriction:"目标限制", secret_redaction:"敏感信息脱敏",
  not_assessed:"证据不足/未评估", candidate:"漏洞候选", confirmed:"已确认漏洞", rejected:"排除漏洞"
};

const steps = [
  {n:1,title:"操作是否真实发生？",help:"导入、函数声明、示例字符串不等于真实效果。看到实际调用或可达实现才选“是”。",fields:[
    {name:"behavior_confirmed",type:"radio",values:["true","false","uncertain"]}
  ]},
  {n:2,title:"是否属于 Agent 的能力或执行路径？",help:"工具注册、Agent 调用链或 Agent 可控制路径属于相关；维护脚本和独立测试通常不相关。",fields:[
    {name:"agent_relevant",type:"radio",values:["true","false","uncertain"]}
  ]},
  {n:3,title:"影响操作的输入来自哪里？",help:"选择最直接、最重要的来源。固定路径、固定命令或硬编码配置属于内部常量。",fields:[
    {name:"source_type",type:"radio",values:["user_prompt","web_content","file_content","tool_output","message_email","database","environment_config","internal_constant","unknown","none"]},
    {name:"source_external",caption:"该来源是否位于当前信任域之外？",type:"radio",values:["true","false","unknown"]}
  ]},
  {n:4,title:"来源能否影响效果，并跨越信任边界？",help:"必须有可追踪的数据流或控制流；仅在同一文件出现只能选部分或未知。",fields:[
    {name:"dependency_confirmed",caption:"来源 → 效果依赖",type:"radio",values:["true","false","partial","unknown"]},
    {name:"trust_boundary_crossed",caption:"发生信任边界跨越",type:"radio",values:["true","false","unknown"]}
  ]},
  {n:5,title:"实际产生了什么安全相关效果？",help:"可以修正扫描器给出的候选类型。目标用一句话写清楚受影响资源。",fields:[
    {name:"effect_type",type:"radio",values:["command_execution","dynamic_code_execution","filesystem_read","filesystem_write","filesystem_delete","browser_control","network_access","credential_access","database_access","external_tool_invocation","other","none"]},
    {name:"effect_target",caption:"效果目标",type:"text",placeholder:"例如：工作区内由用户提供路径指向的文件"}
  ]},
  {n:6,title:"是否存在真正限制危险路径的防护？",help:"日志、异常处理、注释和类型提示通常不是防护。选择“无”时有效性应为“不适用”。",fields:[
    {name:"guard_present",type:"radio",values:["true","false","unknown"]},
    {name:"guard_types",caption:"防护类型（可多选）",type:"checks",values:["allowlist","schema_validation","canonicalization","authorization","user_confirmation","sandbox","escaping","least_privilege","destination_restriction","secret_redaction","other"]},
    {name:"guard_effective",caption:"防护对当前路径是否有效？",type:"radio",values:["yes","no","partial","unknown","not_applicable"]}
  ]},
  {n:7,title:"最终安全结论",help:"危险能力不等于漏洞。确认漏洞需要外部可达、完整依赖、边界跨越、弱点和安全影响均有代码证据。",fields:[
    {name:"weakness_present",caption:"实现中是否存在安全弱点？",type:"radio",values:["true","false","uncertain"]},
    {name:"vulnerability_status",caption:"漏洞状态",type:"radio",values:["not_assessed","candidate","confirmed","rejected"]},
    {name:"label_confidence",caption:"你对整条标注的信心",type:"radio",values:["high","medium","low"]},
    {name:"rationale",caption:"证据理由（必须写行号）",type:"textarea",placeholder:"例如：第 42 行把用户输入直接传给 shell=True；未发现允许列表或确认步骤，因此……"}
  ]}
];

let tasks=[], filtered=[], current=null, currentIndex=0, annotation=null, dirty=false, displayedSource="";
const $=id=>document.getElementById(id);

function fieldHtml(field){
  const caption=field.caption?`<h4>${field.caption}</h4>`:"";
  if(field.type==="text") return `${caption}<input class="text-field" name="${field.name}" placeholder="${field.placeholder||""}">`;
  if(field.type==="textarea") return `${caption}<textarea class="text-field" name="${field.name}" placeholder="${field.placeholder||""}"></textarea>`;
  if(field.type==="checks") return `${caption}<div class="checks">${field.values.map(v=>`<label class="check"><input type="checkbox" name="${field.name}" value="${v}"><span>${labels[v]}</span></label>`).join("")}</div>`;
  return `${caption}<div class="options">${field.values.map(v=>`<label class="choice"><input type="radio" name="${field.name}" value="${v}"><span>${labels[v]}</span></label>`).join("")}</div>`;
}

function buildForm(){
  $("annotationForm").innerHTML=steps.map(s=>`<section class="step"><div class="step-head"><span class="step-no">${s.n}</span><div><h3>${s.title}</h3><p>${s.help}</p></div></div>${s.fields.map(fieldHtml).join("")}</section>`).join("");
  $("annotationForm").addEventListener("input",()=>{dirty=true; applyRules();});
}

function applyRules(){
  const value=name=>document.querySelector(`[name="${name}"]:checked`)?.value;
  if(value("source_type")==="none") choose("source_external","false");
  if(value("dependency_confirmed")==="false") choose("trust_boundary_crossed","false");
  if(value("guard_present")==="false"){
    document.querySelectorAll('[name="guard_types"]').forEach(x=>x.checked=false);
    choose("guard_effective","not_applicable");
  }
}

function choose(name,value){const element=document.querySelector(`[name="${name}"][value="${value}"]`);if(element)element.checked=true;}

async function init(){
  buildForm();
  const response=await apiFetch("/api/tasks");
  if(!response.ok){const error=await response.json();throw new Error(error.error||"邀请链接无效");}
  const data=await response.json(); tasks=data.tasks;
  $("annotator").textContent=`标注者 ${data.annotator} · ${PROVIDER_FREE_NOTICE}`;
  updateFilter();
  const first=tasks.findIndex(t=>t.status!=="completed");
  await openTask(first<0?0:first);
  const introKey=`asb_intro_seen_${INVITE||data.annotator}`;
  if(!localStorage.getItem(introKey))$("intro").showModal();
  $("startReview").onclick=()=>{localStorage.setItem(introKey,"true");$("intro").close();};
}

function updateFilter(){
  const query=$("search").value.trim().toLowerCase(), mode=$("filter").value;
  filtered=tasks.map((t,i)=>({...t,_index:i})).filter(t=>{
    const text=`${t.task_id} ${t.repository} ${t.file} ${t.candidate_behavior}`.toLowerCase();
    return (!query||text.includes(query))&&(mode==="all"||t.status===mode);
  });
  renderList(); updateProgress();
}

function renderList(){
  const container=$("taskList"); container.textContent="";
  for(const task of filtered){
    const button=document.createElement("button");
    button.className=`task-item ${task.status} ${current?.task_id===task.task_id?"active":""}`;
    button.innerHTML='<i class="dot"></i><div><strong></strong><span></span><small></small></div>';
    button.querySelector("strong").textContent=`${task.task_id} · ${labels[task.candidate_behavior]||task.candidate_behavior}`;
    button.querySelector("span").textContent=task.repository;
    button.querySelector("small").textContent=task.file;
    button.onclick=()=>requestOpen(task._index); container.appendChild(button);
  }
}

function updateProgress(){
  const done=tasks.filter(t=>t.status==="completed").length;
  $("progressText").textContent=`${done} / ${tasks.length}`;
  $("progressBar").style.width=`${done/tasks.length*100}%`;
}

async function requestOpen(index){
  if(dirty&&!confirm("当前修改尚未保存，确定离开吗？"))return;
  await openTask(index);
}

async function openTask(index){
  currentIndex=Math.max(0,Math.min(tasks.length-1,index));
  const id=tasks[currentIndex].task_id;
  const response=await apiFetch(`/api/task?id=${encodeURIComponent(id)}`);
  const data=await response.json(); current=data.task; annotation=data.annotation; dirty=false;
  $("taskId").textContent=`${current.task_id} · ${current.candidate_id}`;
  $("candidateBehavior").textContent=labels[current.candidate_behavior]||current.candidate_behavior;
  $("taskMeta").textContent=`${current.repository}  /  ${current.file}  ·  frozen ${current.git_commit.slice(0,12)}`;
  displayedSource=current.source_context; renderCode(); fillForm(); setStatus(annotation._status||"draft"); renderList(); $("errors").classList.add("hidden");
  $("loadFull").classList.toggle("hidden",!current.context_truncated);
  $("loadFull").textContent="加载冻结完整文件";
  $("prev").disabled=currentIndex===0;
  window.scrollTo({top:0,behavior:"smooth"});
}

function renderCode(){
  const code=$("sourceCode").querySelector("code"); code.textContent="";
  const evidence=new Set(current.evidence_lines);
  for(const line of displayedSource.split("\n")){
    const span=document.createElement("span"), match=line.match(/^\s*(\d+)\s+\|/);
    span.className=`code-line ${match&&evidence.has(Number(match[1]))?"evidence":""}`;
    span.textContent=line||" "; code.appendChild(span);
  }
}

function fillForm(){
  $("annotationForm").reset();
  for(const field of steps.flatMap(s=>s.fields)){
    const value=annotation[field.name];
    if(field.type==="radio"&&value!=null)choose(field.name,value);
    else if(field.type==="checks")document.querySelectorAll(`[name="${field.name}"]`).forEach(x=>x.checked=(value||[]).includes(x.value));
    else {const element=document.querySelector(`[name="${field.name}"]`);if(element)element.value=value||"";}
  }
}

function collect(){
  const out={...annotation,task_id:current.task_id,candidate_id:current.candidate_id};
  for(const field of steps.flatMap(s=>s.fields)){
    if(field.type==="radio")out[field.name]=document.querySelector(`[name="${field.name}"]:checked`)?.value??null;
    else if(field.type==="checks")out[field.name]=[...document.querySelectorAll(`[name="${field.name}"]:checked`)].map(x=>x.value);
    else out[field.name]=document.querySelector(`[name="${field.name}"]`).value.trim();
  }
  return out;
}

async function save(complete){
  $("errors").classList.add("hidden");
  const response=await apiFetch("/api/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({task_id:current.task_id,annotation:collect(),complete})});
  const result=await response.json();
  if(!result.ok){showErrors(result.errors||["保存失败"]);return false;}
  annotation=collect(); annotation._status=result.status; dirty=false; tasks[currentIndex].status=result.status;
  setStatus(result.status); updateFilter(); $("saveState").classList.add("flash");setTimeout(()=>$("saveState").classList.remove("flash"),700);
  return true;
}

function showErrors(errors){const box=$("errors");box.innerHTML=`<strong>请修正以下问题：</strong><ul>${errors.map(e=>`<li>${e}</li>`).join("")}</ul>`;box.classList.remove("hidden");box.scrollIntoView({behavior:"smooth",block:"center"});}
function setStatus(status){const e=$("saveState");e.className=`status ${status}`;e.textContent=status==="completed"?"已完成":"未完成/草稿";}
async function nextIncomplete(){for(let offset=1;offset<=tasks.length;offset++){const i=(currentIndex+offset)%tasks.length;if(tasks[i].status!=="completed"){await openTask(i);return;}}alert("150 条任务均已完成。");}

$("search").addEventListener("input",updateFilter);$("filter").addEventListener("change",updateFilter);
$("toggleGuide").onclick=()=>$("guide").classList.toggle("hidden");
$("loadFull").onclick=async()=>{const button=$("loadFull");button.disabled=true;button.textContent="正在读取…";try{const response=await apiFetch(`/api/full-source?id=${encodeURIComponent(current.task_id)}`);const data=await response.json();if(!response.ok)throw new Error(data.error||"读取失败");displayedSource=data.source_context;renderCode();button.textContent="已加载完整文件";}catch(error){showErrors([`完整文件读取失败：${error}`]);button.textContent="重试加载完整文件";}finally{button.disabled=false;}};
$("prev").onclick=()=>requestOpen(currentIndex-1);
$("saveDraft").onclick=()=>save(false);
$("complete").onclick=async()=>{if(await save(true))await nextIncomplete();};
document.addEventListener("keydown",async event=>{if(event.ctrlKey&&event.key.toLowerCase()==="s"){event.preventDefault();await save(false);}if(event.ctrlKey&&event.key==="Enter"){event.preventDefault();if(await save(true))await nextIncomplete();}});
window.addEventListener("beforeunload",event=>{if(dirty){event.preventDefault();event.returnValue="";}});
init().catch(error=>{document.body.innerHTML=`<pre>界面加载失败：${String(error)}</pre>`;});
