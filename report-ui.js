'use strict';
let activeFilter = 'all';
function revealRecord(id) {
  let element = document.getElementById(id);
  while (element) {
    if (element.tagName === 'DETAILS') element.open = true;
    element = element.parentElement;
  }
}
function filterReports(group) {
  activeFilter = group;
  const query = document.getElementById('record-search').value.trim().toLocaleLowerCase();
  let shown = 0;
  const cards = document.querySelectorAll('article[data-tool]');
  cards.forEach(x => {
    const actions = (x.dataset.actions || x.dataset.state || '').split(/\s+/);
    const outside = group !== 'all' && !actions.includes(group);
    x.hidden = outside || !x.textContent.toLocaleLowerCase().includes(query);
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
}
if (typeof document !== 'undefined') {
  filterReports('all');
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
    filterReports(activeFilter);
  });
}
