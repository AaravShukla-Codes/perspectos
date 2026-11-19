"use strict";

/* ==========================================================================
   Helpers shared by every page
   ========================================================================== */
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const page = document.body.dataset.page;

/** Talk to the Flask API. Throws an Error (with the server's message) on failure. */
async function api(method, url, body) {
  const options = { method, credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new Error("Network error. Please check your connection.");
  }
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  if (!response.ok) {
    if (response.status === 401 && url !== "/api/login") {
      location.href = "/login?next=" + encodeURIComponent(location.pathname);
    }
    const error = new Error(data.error || "Something went wrong.");
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

/** Build a DOM element. Strings become TEXT nodes, so user content can never inject HTML. */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) if (child != null) node.append(child);
  return node;
}

function timeAgo(isoString) {
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = Math.floor(seconds / size);
      return `${n} ${name}${n > 1 ? "s" : ""} ago`;
    }
  }
  return "just now";
}

let toastTimer;
function showToast(message) {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = el("div", { id: "toast", role: "status" });
    document.body.append(toast);
  }
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3500);
}

function showError(id, message) {
  const box = document.getElementById(id);
  box.textContent = message;
  box.hidden = !message;
}

/** Run an async form handler: disables the submit button and shows errors. */
function handleForm(form, errorId, action) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    showError(errorId, "");
    try {
      await action(Object.fromEntries(new FormData(form)));
    } catch (error) {
      showError(errorId, error.message);
    } finally {
      button.disabled = false;
    }
  });
}

function safeNext() {
  const next = new URLSearchParams(location.search).get("next");
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : "/";
}

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

/* ==========================================================================
   Every page: log out button, dialog close buttons
   ========================================================================== */
document.getElementById("logout-btn")?.addEventListener("click", async () => {
  await api("POST", "/api/logout");
  location.href = "/";
});

document.querySelectorAll("dialog [data-close]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog").close());
});

/* ==========================================================================
   Login and register
   ========================================================================== */
function initLogin() {
  handleForm(document.getElementById("login-form"), "form-error", async (values) => {
    await api("POST", "/api/login", values);
    location.href = safeNext();
  });
}

function initRegister() {
  handleForm(document.getElementById("register-form"), "form-error", async (values) => {
    await api("POST", "/api/register", values);
    location.href = "/";
  });
}

/* ==========================================================================
   Home page: search, categories, topic lists
   ========================================================================== */
function topicCard(topic) {
  return el("a", { class: "topic-card", href: `/topic/${topic.id}` },
    el("span", { class: "topic-card-word", text: topic.word }),
    topic.description ? el("span", { class: "topic-card-desc", text: topic.description }) : null,
    el("span", { class: "topic-card-meta" },
      el("span", { class: "badge", text: topic.category }),
      el("span", { text: plural(topic.comment_count, "perspective") }),
      el("span", { text: `by ${topic.author}` })));
}

function topicQuery({ q = "", category = "", sort = "recent", limit = 12, offset = 0 }) {
  const params = new URLSearchParams({ sort, limit, offset });
  if (q) params.set("q", q);
  if (category) params.set("category", category);
  return "/api/topics?" + params.toString();
}

function initIndex() {
  const urlParams = new URLSearchParams(location.search);
  const state = {
    q: (urlParams.get("q") || "").slice(0, 50),
    category: urlParams.get("category") || "",
    sort: urlParams.get("sort") || "recent",
    browse: urlParams.get("browse") === "1",
    offset: 0,
  };
  const PAGE_SIZE = 12;

  const homeSections = document.getElementById("home-sections");
  const results = document.getElementById("results");
  const resultsList = document.getElementById("results-list");
  const resultsEmpty = document.getElementById("results-empty");
  const loadMore = document.getElementById("load-more");
  const sortSelect = document.getElementById("sort-select");
  const searchInput = document.getElementById("search-input");
  const chips = document.querySelectorAll("#category-chips .chip");

  function syncUrl() {
    const params = new URLSearchParams();
    if (state.q) params.set("q", state.q);
    if (state.category) params.set("category", state.category);
    if (state.browse || state.q || state.category) params.set("sort", state.sort);
    if (state.browse) params.set("browse", "1");
    const query = params.toString();
    history.replaceState(null, "", query ? "?" + query : location.pathname);
  }

  function markChips() {
    chips.forEach((chip) => chip.classList.toggle("active", chip.dataset.category === state.category));
  }

  async function loadHome() {
    homeSections.hidden = false;
    results.hidden = true;
    const lists = { trending: "trending", recent: "recent", discussed: "discussed" };
    await Promise.all(Object.entries(lists).map(async ([id, sort]) => {
      const container = document.getElementById("list-" + id);
      try {
        const data = await api("GET", topicQuery({ sort, limit: 6 }));
        container.replaceChildren(...data.topics.map(topicCard));
        if (!data.topics.length) container.append(el("p", { class: "muted", text: "No topics yet. Be the first to share a word!" }));
      } catch (error) {
        container.replaceChildren(el("p", { class: "form-error", text: error.message }));
      }
    }));
  }

  async function loadResults(append = false) {
    homeSections.hidden = true;
    results.hidden = false;
    sortSelect.value = state.sort;
    if (!append) state.offset = 0;

    let title = "All topics";
    if (state.q && state.category) title = `“${state.q}” in ${state.category}`;
    else if (state.q) title = `Results for “${state.q}”`;
    else if (state.category) title = state.category;
    document.getElementById("results-title").textContent = title;

    try {
      const data = await api("GET", topicQuery({ ...state, limit: PAGE_SIZE, offset: state.offset }));
      const cards = data.topics.map(topicCard);
      if (append) resultsList.append(...cards);
      else resultsList.replaceChildren(...cards);
      state.offset += data.topics.length;
      resultsEmpty.hidden = state.offset > 0;
      loadMore.hidden = !data.has_more;
    } catch (error) {
      showToast(error.message);
    }
  }

  function refresh() {
    markChips();
    syncUrl();
    if (state.q || state.category || state.browse) loadResults();
    else loadHome();
  }

  document.getElementById("search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    state.q = searchInput.value.trim();
    refresh();
  });

  chips.forEach((chip) => chip.addEventListener("click", () => {
    state.category = chip.dataset.category;
    refresh();
  }));

  document.querySelectorAll("[data-see-all]").forEach((button) => button.addEventListener("click", () => {
    state.sort = button.dataset.seeAll;
    state.browse = true;
    refresh();
  }));

  sortSelect.addEventListener("change", () => {
    state.sort = sortSelect.value;
    refresh();
  });

  document.getElementById("clear-btn").addEventListener("click", () => {
    Object.assign(state, { q: "", category: "", browse: false, sort: "recent" });
    searchInput.value = "";
    refresh();
  });

  loadMore.addEventListener("click", () => loadResults(true));

  // Create-topic dialog (only exists when logged in)
  const createDialog = document.getElementById("create-dialog");
  if (createDialog) {
    document.getElementById("create-btn").addEventListener("click", () => {
      showError("create-error", "");
      createDialog.showModal();
      document.getElementById("create-word").focus();
    });
    const form = document.getElementById("create-form");
    handleForm(form, "create-error", async (values) => {
      try {
        const data = await api("POST", "/api/topics", values);
        location.href = `/topic/${data.topic.id}`;
      } catch (error) {
        if (error.status === 409 && error.data.topic_id) {
          showToast("That word already has a discussion. Taking you there…");
          location.href = `/topic/${error.data.topic_id}`;
          return;
        }
        throw error;
      }
    });
  }

  searchInput.value = state.q;
  refresh();
}

/* ==========================================================================
   Topic page: comments, replies, reactions, edit, delete, report
   ========================================================================== */
function initTopic() {
  const root = document.getElementById("topic-page");
  const topicId = Number(root.dataset.topicId);
  const loggedIn = root.dataset.loggedIn === "1";
  const commentsBox = document.getElementById("comments");
  const emptyMsg = document.getElementById("comments-empty");
  const sortSelect = document.getElementById("comment-sort");
  let comments = [];

  function updateCounts() {
    document.getElementById("comment-count").textContent = comments.length;
    document.getElementById("comment-count-top").textContent = comments.length;
    emptyMsg.hidden = comments.length > 0;
  }

  function sortComments(list) {
    const mode = sortSelect.value;
    const copy = [...list];
    if (mode === "newest") copy.sort((a, b) => b.id - a.id);
    else if (mode === "top") copy.sort((a, b) => (b.likes - b.dislikes) - (a.likes - a.dislikes) || b.id - a.id);
    else copy.sort((a, b) => a.id - b.id);
    return copy;
  }

  function render() {
    const children = new Map();
    for (const c of comments) {
      const key = c.parent_id ?? 0;
      if (!children.has(key)) children.set(key, []);
      children.get(key).push(c);
    }

    function build(comment, depth) {
      const replies = (children.get(comment.id) || []).sort((a, b) => a.id - b.id);
      const node = renderComment(comment, replies, depth, build);
      return node;
    }

    const top = sortComments(children.get(0) || []);
    commentsBox.replaceChildren(...top.map((c) => build(c, 0)));
    updateCounts();
  }

  function renderComment(comment, replies, depth, build) {
    const slot = el("div");
    const likeBtn = el("button", { class: "act", type: "button" });
    const dislikeBtn = el("button", { class: "act", type: "button" });

    function paintReactions() {
      likeBtn.textContent = `Like ${comment.likes}`;
      dislikeBtn.textContent = `Dislike ${comment.dislikes}`;
      likeBtn.classList.toggle("on", comment.my_reaction === 1);
      dislikeBtn.classList.toggle("on", comment.my_reaction === -1);
      likeBtn.setAttribute("aria-pressed", comment.my_reaction === 1);
      dislikeBtn.setAttribute("aria-pressed", comment.my_reaction === -1);
    }

    async function react(value) {
      // clicking the same reaction again removes it
      const next = comment.my_reaction === value ? 0 : value;
      try {
        const data = await api("POST", `/api/comments/${comment.id}/react`, { value: next });
        Object.assign(comment, data);
        paintReactions();
      } catch (error) {
        showToast(error.message);
      }
    }
    likeBtn.addEventListener("click", () => react(1));
    dislikeBtn.addEventListener("click", () => react(-1));
    paintReactions();

    function openForm(kind) {
      if (slot.firstChild && slot.dataset.kind === kind) { slot.replaceChildren(); return; }
      slot.dataset.kind = kind;
      const area = el("textarea", { maxlength: 1000, rows: 3, required: true, "aria-label": kind === "edit" ? "Edit comment" : "Write a reply" });
      if (kind === "edit") area.value = comment.body;
      const error = el("p", { class: "form-error", role: "alert", hidden: true });
      const submit = el("button", { class: "btn btn-small btn-primary", type: "submit", text: kind === "edit" ? "Save" : "Reply" });
      const cancel = el("button", { class: "btn btn-small", type: "button", text: "Cancel", onclick: () => slot.replaceChildren() });
      const form = el("form", { class: "inline-form" }, area, error, el("div", { class: "row" }, submit, cancel));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        error.hidden = true;
        try {
          if (kind === "edit") {
            const data = await api("PUT", `/api/comments/${comment.id}`, { body: area.value });
            Object.assign(comment, data.comment);
          } else {
            const data = await api("POST", `/api/topics/${topicId}/comments`, { body: area.value, parent_id: comment.id });
            comments.push(data.comment);
          }
          render();
        } catch (err) {
          error.textContent = err.message;
          error.hidden = false;
          submit.disabled = false;
        }
      });
      slot.replaceChildren(form);
      area.focus();
    }

    const actions = el("div", { class: "comment-actions" }, likeBtn, dislikeBtn);
    if (loggedIn) actions.append(el("button", { class: "act", type: "button", text: "Reply", onclick: () => openForm("reply") }));
    if (comment.mine) actions.append(el("button", { class: "act", type: "button", text: "Edit", onclick: () => openForm("edit") }));
    if (comment.can_delete) {
      actions.append(el("button", {
        class: "act danger", type: "button", text: "Delete",
        onclick: async () => {
          const extra = replies.length ? " Its replies will be deleted too." : "";
          if (!confirm("Delete this comment?" + extra)) return;
          try {
            await api("DELETE", `/api/comments/${comment.id}`);
            await loadComments();
          } catch (error) {
            showToast(error.message);
          }
        },
      }));
    }
    if (loggedIn && !comment.mine) {
      actions.append(el("button", { class: "act", type: "button", text: "Report", onclick: () => openReport("comment", comment.id) }));
    }

    const head = el("div", { class: "comment-head" },
      el("a", { class: "comment-author", href: `/user/${encodeURIComponent(comment.author)}`, text: comment.author }),
      el("span", { class: "muted", text: timeAgo(comment.created_at), title: new Date(comment.created_at).toLocaleString() }),
      comment.edited_at ? el("span", { class: "muted", text: "(edited)" }) : null);

    const repliesBox = replies.length
      ? el("div", { class: depth >= 3 ? "replies flat" : "replies" }, replies.map((r) => build(r, depth + 1)))
      : null;

    return el("div", { class: "comment", id: `comment-${comment.id}` },
      head, el("p", { class: "comment-body", text: comment.body }), actions, slot, repliesBox);
  }

  async function loadComments() {
    try {
      const data = await api("GET", `/api/topics/${topicId}/comments`);
      comments = data.comments;
      render();
    } catch (error) {
      showToast(error.message);
    }
  }

  sortSelect.addEventListener("change", render);

  // New top-level comment
  const commentForm = document.getElementById("comment-form");
  if (commentForm) {
    const input = document.getElementById("comment-input");
    commentForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = commentForm.querySelector('button[type="submit"]');
      button.disabled = true;
      showError("comment-error", "");
      try {
        const data = await api("POST", `/api/topics/${topicId}/comments`, { body: input.value });
        comments.push(data.comment);
        input.value = "";
        render();
      } catch (error) {
        showError("comment-error", error.message);
      } finally {
        button.disabled = false;
      }
    });
  }

  // Report dialog (topic or comment)
  const reportDialog = document.getElementById("report-dialog");
  let reportTarget = null;
  function openReport(type, id) {
    reportTarget = { type, id };
    document.getElementById("report-what").textContent = type;
    reportDialog.querySelector("textarea").value = "";
    showError("report-error", "");
    reportDialog.showModal();
  }
  if (reportDialog) {
    handleForm(document.getElementById("report-form"), "report-error", async (values) => {
      await api("POST", "/api/report", { ...reportTarget, reason: values.reason });
      reportDialog.close();
      showToast("Thanks. A moderator will review this.");
    });
  }
  document.getElementById("report-topic-btn")?.addEventListener("click", () => openReport("topic", topicId));

  // Edit / delete topic
  const editDialog = document.getElementById("edit-topic-dialog");
  document.getElementById("edit-topic-btn")?.addEventListener("click", () => editDialog.showModal());
  if (editDialog) {
    handleForm(document.getElementById("edit-topic-form"), "edit-topic-error", async (values) => {
      await api("PUT", `/api/topics/${topicId}`, values);
      location.reload();
    });
  }
  document.getElementById("delete-topic-btn")?.addEventListener("click", async () => {
    if (!confirm("Delete this topic and every comment in it? This cannot be undone.")) return;
    try {
      await api("DELETE", `/api/topics/${topicId}`);
      location.href = "/";
    } catch (error) {
      showToast(error.message);
    }
  });

  loadComments();
}

/* ==========================================================================
   Profile page: edit profile
   ========================================================================== */
function initProfile() {
  const form = document.getElementById("profile-form");
  if (!form) return;
  handleForm(form, "form-error", async (values) => {
    const data = await api("PUT", "/api/profile", values);
    location.href = `/user/${encodeURIComponent(data.username)}`;
  });
}

/* ==========================================================================
   Admin page: review reports
   ========================================================================== */
function initAdmin() {
  const box = document.getElementById("reports");
  const empty = document.getElementById("reports-empty");
  const statusSelect = document.getElementById("report-status");

  async function load() {
    try {
      const data = await api("GET", `/api/admin/reports?status=${statusSelect.value}`);
      box.replaceChildren(...data.reports.map(reportCard));
      empty.hidden = data.reports.length > 0;
    } catch (error) {
      showToast(error.message);
    }
  }

  function reportCard(report) {
    async function act(kind, confirmText) {
      if (confirmText && !confirm(confirmText)) return;
      try {
        await api("POST", `/api/admin/reports/${report.id}/${kind}`);
        showToast(kind === "remove" ? "Content removed." : "Report dismissed.");
        load();
      } catch (error) {
        showToast(error.message);
      }
    }
    const what = report.type === "topic" ? `Topic “${report.topic_word}”` : `Comment on “${report.topic_word}”`;
    const actions = el("div", { class: "row" },
      el("a", { class: "btn btn-small", href: `/topic/${report.topic_id}`, text: "View" }));
    if (report.status === "open") {
      actions.append(
        el("button", { class: "btn btn-small", type: "button", text: "Dismiss", onclick: () => act("dismiss") }),
        el("button", {
          class: "btn btn-small btn-danger", type: "button", text: "Remove content",
          onclick: () => act("remove", `Permanently remove this ${report.type}${report.type === "topic" ? " and all its comments" : " and its replies"}?`),
        }));
    }
    return el("article", { class: "card report-card" },
      el("strong", { text: what }),
      el("p", { class: "report-quote", text: report.preview || "(no text)" }),
      el("p", { class: "muted", text: `By ${report.author} · reported by ${report.reporter} ${timeAgo(report.created_at)}` }),
      el("p", {}, el("strong", { text: "Reason: " }), report.reason),
      actions);
  }

  statusSelect.addEventListener("change", load);
  load();
}

/* ==========================================================================
   Start the right code for this page
   ========================================================================== */
const pages = { login: initLogin, register: initRegister, index: initIndex, topic: initTopic, profile: initProfile, admin: initAdmin };
pages[page]?.();
