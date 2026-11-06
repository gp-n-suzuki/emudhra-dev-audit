'use strict';
let activeFilter = 'all';
let selectedTool = '';
function navigation() {
  return document.getElementById('tool-navigation');
}
function selectTool(id, focus = false, revealNavigation = true) {
  selectedTool = id;
  if (!navigation()) return;
  document.querySelectorAll('article[data-tool]').forEach(card => {
    card.hidden = card.dataset.eligible !== 'true' || card.id !== id;
  });
  document.querySelectorAll('button[data-select]').forEach(button => {
    button.setAttribute('aria-pressed', String(button.dataset.select === id));
    if (revealNavigation && button.dataset.select === id) {
      const group = button.closest?.('details');
      if (group) group.open = true;
    }
  });
  document.querySelectorAll('[data-result-group]').forEach(section => {
    section.hidden = !Array.from(section.querySelectorAll('article[data-tool]')).some(card => !card.hidden);
  });
  if (focus) {
    const heading = document.getElementById(id)?.querySelector('.selected-tool-heading');
    if (heading) { heading.tabIndex = -1; heading.focus({preventScroll:true}); }
  }
}
async function copyPrompt(id) {
  const field = document.getElementById(id);
  const status = document.getElementById(id + '-status');
  try {
    await navigator.clipboard.writeText(field.value);
    status.textContent = '編集後のプロンプトをコピーしました。使いたいAIへ貼り付けてください。';
  } catch (_) {
    field.focus(); field.select();
    status.textContent = '自動コピーできませんでした。選択した文章を手動でコピーしてください。';
  }
}
function revealRecord(id) {
  let element = document.getElementById(id);
  if (navigation() && element) {
    const card = element.closest('article[data-tool]');
    if (card) {
      document.getElementById('record-search').value = '';
      selectedTool = card.id;
      filterReports('all');
    }
  }
  while (element) {
    if (element.tagName === 'DETAILS') element.open = true;
    element = element.parentElement;
  }
}
function filterReports(group, preserveDisclosure = false) {
  activeFilter = group;
  const query = document.getElementById('record-search').value.trim().toLocaleLowerCase();
  let shown = 0;
  const cards = document.querySelectorAll('article[data-tool]');
  cards.forEach(x => {
    const actions = (x.dataset.actions || x.dataset.state || '').split(/\s+/);
    const outside = group !== 'all' && !actions.includes(group);
    x.hidden = outside || !(x.dataset.search || x.textContent).toLocaleLowerCase().includes(query);
    x.dataset.eligible = String(!x.hidden);
    if (!x.hidden) shown++;
  });
  document.querySelectorAll('[data-result-group]').forEach(section => {
    const visible = Array.from(section.querySelectorAll('article[data-tool]')).filter(row => !row.hidden).length;
    section.hidden = visible === 0;
    section.querySelector('h2 span').textContent = `${visible}ツール`;
  });
  document.querySelectorAll('button[data-filter]').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.filter === group)));
  document.getElementById('result-count').textContent = `${shown} / ${cards.length}ツール`;
  document.getElementById('empty-results').hidden = shown > 0;
  if (navigation()) {
    const eligible = Array.from(cards).filter(card => card.dataset.eligible === 'true');
    const choices = Array.from(document.querySelectorAll('button[data-select]'));
    choices.forEach(button => {
      button.hidden = !eligible.some(card => card.id === button.dataset.select);
    });
    document.querySelectorAll('[data-navigation-group]').forEach(group => {
      const matched = Array.from(group.querySelectorAll('button[data-select]')).filter(button => !button.hidden);
      group.hidden = !matched.length;
      group.querySelector('summary span').textContent = String(matched.length);
    });
    selectTool(eligible.some(card => card.id === selectedTool) ? selectedTool : (choices.find(button => !button.hidden)?.dataset.select || ''), false, !preserveDisclosure);
  }
}
if (typeof document !== 'undefined') {
  filterReports('all');
  if (window.location?.hash) revealRecord(window.location.hash.slice(1));
  window.addEventListener('hashchange', () => revealRecord(window.location.hash.slice(1)));
  let printDetails = [];
  let printHidden = [];
  window.addEventListener('beforeprint', () => {
    printHidden = Array.from(document.querySelectorAll('[hidden]'));
    printHidden.forEach(x => x.hidden = false);
    printDetails = Array.from(document.querySelectorAll('details')).filter(x => !x.open);
    printDetails.forEach(x => x.open = true);
    document.querySelectorAll('[data-result-group]').forEach(section => {
      section.querySelector('h2 span').textContent = `${section.querySelectorAll('article[data-tool]').length}ツール`;
    });
  });
  window.addEventListener('afterprint', () => {
    printDetails.forEach(x => x.open = false);
    printHidden.forEach(x => x.hidden = true);
    filterReports(activeFilter, true);
  });
}
