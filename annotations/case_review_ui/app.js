const state = {tasks: [], currentId: null, payload: null, invite: null};
const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
}

function readInvite() {
  const match = location.hash.match(/(?:^#|&)invite=([^&]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (state.invite) headers["X-Annotation-Invite"] = state.invite;
  const response = await fetch(path, {...options, headers});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || (data.errors || []).join("\n") || "请求失败");
  return data;
}

function statusText(value) {
  return ({confirmed:"辅助确认", candidate:"辅助候选", completed:"已完成", draft:"未完成"})[value] || value || "未完成";
}

function labelText(field, value) {
  const labels = {
    reachability:{documented_default:"默认部署可达",conditional:"条件可达",not_reachable:"不可达",unknown:"证据不足"},
    caller_trust:{untrusted_or_model:"不可信输入可控",trusted_only:"仅可信内部调用",unknown:"来源不明确"},
    access_control:{absent:"没有防护",present_ineffective:"防护无效或不完整",present_effective:"防护有效",unknown:"无法判断"},
    case_relation:{new_case:"建立新案例",merge_existing:"合并已有案例",not_security_case:"不形成安全案例",unknown:"暂不确定"},
    final_case_label:{confirmed_vulnerability:"确认漏洞",vulnerability_candidate:"漏洞候选",unsafe_capability:"危险能力",rejected:"排除",insufficient_context:"上下文不足"}
  };
  return labels[field]?.[value] || value || "—";
}

function filteredTasks() {
  const query = $("search").value.trim().toLowerCase();
  const filter = $("filter").value;
  return state.tasks.filter(task => {
    const haystack = `${task.task_id} ${task.repository} ${task.file} ${task.candidate_behavior}`.toLowerCase();
    if (query && !haystack.includes(query)) return false;
    if (filter === "draft" && task.status === "completed") return false;
    if (filter === "completed" && task.status !== "completed") return false;
    if (filter === "confirmed" && task.assisted_status !== "confirmed") return false;
    if (filter === "candidate" && task.assisted_status !== "candidate") return false;
    return true;
  });
}

function renderTaskList() {
  const grouped = new Map();
  for (const task of filteredTasks()) {
    if (!grouped.has(task.repository)) grouped.set(task.repository, []);
    grouped.get(task.repository).push(task);
  }
  const html = [...grouped.entries()].map(([repo, tasks]) => `
    <section class="repo-group"><h4>${escapeHtml(repo)} · ${tasks.length}</h4>
      ${tasks.map(task => `
        <button class="task-button ${task.task_id === state.currentId ? "active" : ""}" data-id="${escapeHtml(task.task_id)}">
          <span class="line1"><b>${escapeHtml(task.task_id)} · ${escapeHtml(task.candidate_behavior)}</b><i class="dot ${task.status === "completed" ? "completed" : ""}"></i></span>
          <span class="assisted-mark">${statusText(task.assisted_status)}</span>
          <small>${escapeHtml(task.file)}</small>
        </button>`).join("")}
    </section>`).join("");
  $("taskList").innerHTML = html || '<p class="count-note">没有匹配的任务</p>';
  document.querySelectorAll(".task-button").forEach(button => button.addEventListener("click", () => loadTask(button.dataset.id)));
}

function updateProgress() {
  const completed = state.tasks.filter(task => task.status === "completed").length;
  $("progressText").textContent = `${completed} / ${state.tasks.length}`;
  $("progressBar").style.width = `${state.tasks.length ? completed / state.tasks.length * 100 : 0}%`;
}

function renderCode(context, evidenceLines) {
  const evidence = new Set(evidenceLines || []);
  const html = String(context || "").split("\n").map(raw => {
    const match = raw.match(/^\s*(\d+)\s*\|\s?(.*)$/);
    const number = match ? Number(match[1]) : null;
    const text = match ? match[2] : raw;
    return `<div class="code-line ${evidence.has(number) ? "evidence" : ""}" data-line="${number || ""}"><span class="num">${number || ""}</span><span>${escapeHtml(text)}</span></div>`;
  }).join("");
  $("sourceCode").innerHTML = html;
  setTimeout(() => $("sourceCode").querySelector(".evidence")?.scrollIntoView({block:"center"}), 20);
}

function renderRepositoryEvidence(evidence) {
  const box = $("repositoryEvidence");
  if (!evidence) { box.classList.add("hidden"); box.innerHTML = ""; $("useSuggestion").classList.add("hidden"); return; }
  box.innerHTML = `<h3>仓库级补充证据 · 建议聚类 ${escapeHtml(evidence.proposed_case_id)}</h3>
    <p>这些内容来自候选窗口之外，用于验证默认部署和实际调用链。建议不是最终答案。</p>
    <ol>${evidence.items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
  box.classList.remove("hidden");
  $("useSuggestion").classList.remove("hidden");
}

function renderAssisted(task) {
  const labels = task.audit_labels || {};
  $("assistedSummary").innerHTML = `
    <div class="assisted-grid">
      <div class="mini"><small>辅助状态</small><b>${escapeHtml(task.assisted_status)}</b></div>
      <div class="mini"><small>信任边界</small><b>${escapeHtml(labels.trust_boundary_crossed)}</b></div>
      <div class="mini"><small>防护</small><b>${escapeHtml(labels.guard_present)} / ${escapeHtml(labels.guard_effective)}</b></div>
    </div>
    <p><b>理由：</b>${escapeHtml(task.audit_rationale)}</p>
    <p><b>缺失上下文：</b>${escapeHtml(task.audit_note || "无")}</p>`;
}

function renderModels(task) {
  $("modelDetails").innerHTML = Object.entries(task.model_annotations || {}).map(([provider, annotation]) => `
    <article class="model-item"><h4>${escapeHtml(provider)}</h4>
      <p><b>漏洞状态：</b>${escapeHtml(annotation.vulnerability_status)}　<b>弱点：</b>${escapeHtml(annotation.weakness_present)}　<b>信心：</b>${escapeHtml(annotation.label_confidence)}</p>
      <p>${escapeHtml(annotation.rationale)}</p>
      ${annotation.missing_context ? `<p><b>缺失：</b>${escapeHtml(annotation.missing_context)}</p>` : ""}
    </article>`).join("");
}

function renderSourceReview(reviewer, review) {
  const card = $("sourceReviewCard");
  if (!review) {
    card.classList.add("hidden");
    $("sourceReview").innerHTML = "";
    return;
  }
  $("sourceReviewerName").textContent = reviewer || "前序审核者";
  const relationTarget = review.case_relation === "new_case" ? review.case_id : review.merge_into_case_id;
  $("sourceReview").innerHTML = `
    <div class="source-review-grid">
      <div class="mini"><small>可达性</small><b>${escapeHtml(labelText("reachability", review.reachability))}</b></div>
      <div class="mini"><small>输入来源</small><b>${escapeHtml(labelText("caller_trust", review.caller_trust))}</b></div>
      <div class="mini"><small>访问控制</small><b>${escapeHtml(labelText("access_control", review.access_control))}</b></div>
      <div class="mini"><small>最终标签</small><b>${escapeHtml(labelText("final_case_label", review.final_case_label))}</b></div>
    </div>
    <p><b>案例关系：</b>${escapeHtml(labelText("case_relation", review.case_relation))}${relationTarget ? ` · ${escapeHtml(relationTarget)}` : ""}</p>
    <p><b>影响：</b>${escapeHtml((review.impacts || []).join("、") || "无")}</p>
    <p><b>共同根因：</b>${escapeHtml(review.root_cause)}</p>
    <p><b>证据：</b>${escapeHtml(review.evidence_refs)}</p>
    <p><b>理由：</b>${escapeHtml(review.rationale)}</p>
    <p><b>仍缺少：</b>${escapeHtml(review.missing_context || "无")}</p>`;
  card.classList.remove("hidden");
}

function setRadio(name, value) {
  document.querySelectorAll(`input[name="${name}"]`).forEach(input => input.checked = input.value === value);
}

function populateForm(annotation) {
  Object.keys({reachability:1,caller_trust:1,access_control:1,case_relation:1,final_case_label:1}).forEach(field => setRadio(field, annotation[field]));
  document.querySelectorAll("#impactChecks input").forEach(input => input.checked = (annotation.impacts || []).includes(input.value));
  $("caseId").value = annotation.case_id || "";
  $("caseTitle").value = annotation.case_title || "";
  $("mergeInto").value = annotation.merge_into_case_id || "";
  $("rootCause").value = annotation.root_cause || "";
  $("evidenceRefs").value = annotation.evidence_refs || "";
  $("rationale").value = annotation.rationale || "";
  $("missingContext").value = annotation.missing_context || "";
  updateRelationFields();
}

function collectForm() {
  const current = state.payload.annotation;
  const radio = name => document.querySelector(`input[name="${name}"]:checked`)?.value || null;
  return {
    ...current,
    task_id: state.currentId,
    candidate_id: state.payload.task.candidate_id,
    reachability: radio("reachability"),
    caller_trust: radio("caller_trust"),
    access_control: radio("access_control"),
    impacts: [...document.querySelectorAll("#impactChecks input:checked")].map(input => input.value),
    case_relation: radio("case_relation"),
    case_id: $("caseId").value.trim(),
    case_title: $("caseTitle").value.trim(),
    merge_into_case_id: $("mergeInto").value.trim(),
    root_cause: $("rootCause").value.trim(),
    final_case_label: radio("final_case_label"),
    evidence_refs: $("evidenceRefs").value.trim(),
    rationale: $("rationale").value.trim(),
    missing_context: $("missingContext").value.trim(),
  };
}

function updateRelationFields() {
  const relation = document.querySelector('input[name="case_relation"]:checked')?.value;
  $("caseIdWrap").classList.toggle("hidden", relation !== "new_case");
  $("mergeIdWrap").classList.toggle("hidden", relation !== "merge_existing");
}

async function loadTask(taskId) {
  try {
    state.currentId = taskId;
    state.payload = await api(`/api/task?id=${encodeURIComponent(taskId)}`);
    const {task, annotation, repository_evidence: repositoryEvidence, source_reviewer: sourceReviewer, source_review: sourceReview} = state.payload;
    $("taskId").textContent = task.task_id;
    $("behavior").textContent = task.candidate_behavior;
    $("meta").textContent = `${task.repository} · ${task.file} · lines ${task.evidence_lines.join(", ")}`;
    $("assistedStatus").textContent = statusText(task.assisted_status);
    $("saveState").textContent = annotation._status === "completed" ? "已完成" : "未完成";
    $("saveState").className = `save-state ${annotation._status === "completed" ? "completed" : "draft"}`;
    renderCode(task.source_context, task.evidence_lines);
    $("loadFull").classList.toggle("hidden", !task.context_truncated);
    renderRepositoryEvidence(repositoryEvidence);
    renderAssisted(task);
    renderSourceReview(sourceReviewer, sourceReview);
    renderModels(task);
    populateForm(annotation);
    $("errors").classList.add("hidden");
    renderTaskList();
    window.scrollTo({top:0,behavior:"smooth"});
  } catch (error) { showErrors([error.message]); }
}

function showErrors(errors) {
  $("errors").innerHTML = `<b>请补全以下内容：</b><ul>${errors.map(error => `<li>${escapeHtml(error)}</li>`).join("")}</ul>`;
  $("errors").classList.remove("hidden");
  $("errors").scrollIntoView({behavior:"smooth",block:"center"});
}

async function save(complete) {
  if (!state.currentId) return;
  try {
    const annotation = collectForm();
    const result = await api("/api/save", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({task_id:state.currentId,annotation,complete})});
    state.payload.annotation = {...annotation,_status:result.status};
    const task = state.tasks.find(item => item.task_id === state.currentId);
    task.status = result.status;
    task.final_case_label = annotation.final_case_label;
    task.case_id = annotation.case_id;
    task.merge_into_case_id = annotation.merge_into_case_id;
    updateProgress(); renderTaskList();
    $("saveState").textContent = complete ? "已完成" : "草稿已保存";
    $("saveState").className = `save-state ${complete ? "completed" : "draft"}`;
    $("errors").classList.add("hidden");
    if (complete) {
      const index = state.tasks.findIndex(item => item.task_id === state.currentId);
      const next = [...state.tasks.slice(index + 1), ...state.tasks.slice(0, index)].find(item => item.status !== "completed");
      if (next) await loadTask(next.task_id);
      else alert("本审核者的 19 条案例复核已全部完成。结果已保存。 ");
    }
  } catch (error) { showErrors(String(error.message).split("\n").filter(Boolean)); }
}

async function loadFullSource() {
  try {
    $("loadFull").textContent = "载入中…";
    const data = await api(`/api/full-source?id=${encodeURIComponent(state.currentId)}`);
    renderCode(data.source_context, state.payload.task.evidence_lines);
    $("loadFull").textContent = "已加载完整文件";
    $("loadFull").disabled = true;
  } catch (error) { showErrors([error.message]); $("loadFull").textContent = "加载完整文件"; }
}

function move(offset) {
  const index = state.tasks.findIndex(item => item.task_id === state.currentId);
  if (index < 0) return;
  const next = state.tasks[(index + offset + state.tasks.length) % state.tasks.length];
  loadTask(next.task_id);
}

async function start() {
  state.invite = readInvite();
  try {
    const data = await api("/api/tasks");
    state.tasks = data.tasks;
    $("reviewer").textContent = `审核者 ${data.annotator}`;
    updateProgress(); renderTaskList();
    const first = state.tasks.find(task => task.status !== "completed") || state.tasks[0];
    if (first) await loadTask(first.task_id);
  } catch (error) { document.body.innerHTML = `<main style="padding:40px"><h1>无法打开审核台</h1><p>${escapeHtml(error.message)}</p></main>`; }
}

$("search").addEventListener("input", renderTaskList);
$("filter").addEventListener("change", renderTaskList);
$("loadFull").addEventListener("click", loadFullSource);
$("saveDraft").addEventListener("click", () => save(false));
$("complete").addEventListener("click", () => save(true));
$("prev").addEventListener("click", () => move(-1));
document.querySelectorAll('input[name="case_relation"]').forEach(input => input.addEventListener("change", updateRelationFields));
$("impactChecks").addEventListener("change", event => {
  if (event.target.value === "none" && event.target.checked) document.querySelectorAll('#impactChecks input:not([value="none"])').forEach(input => input.checked = false);
  if (event.target.value !== "none" && event.target.checked) document.querySelector('#impactChecks input[value="none"]').checked = false;
});
$("useSuggestion").addEventListener("click", () => {
  const evidence = state.payload.repository_evidence;
  if (!evidence) return;
  setRadio("case_relation", state.currentId === "AT-0032" ? "new_case" : "merge_existing");
  if (state.currentId === "AT-0032") $("caseId").value = evidence.proposed_case_id;
  else $("mergeInto").value = evidence.proposed_case_id;
  $("caseTitle").value = evidence.proposed_title;
  updateRelationFields();
});
$("adoptSourceReview").addEventListener("click", () => {
  const source = state.payload?.source_review;
  if (!source) return;
  populateForm({...state.payload.annotation, ...source, reviewer: state.payload.annotator});
  $("saveState").textContent = "已填入前序结论，尚未保存";
  $("saveState").className = "save-state draft";
});
window.addEventListener("keydown", event => {
  if (event.ctrlKey && event.key.toLowerCase() === "s") { event.preventDefault(); save(false); }
  if (event.ctrlKey && event.key === "Enter") { event.preventDefault(); save(true); }
});

start();
