const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function page(actionMode = false) {
  const cards = [
    ['action review', 'Java 要対応 /jdk/bin/java 接続テスト未実施'], ['review', 'PHP 原因の確認が必要'],
    ['complete', 'curl 検査用サイトへの接続をブロック'], ['scope', '.NET 見つからない'], ['info', 'OpenSSL 環境情報のみ']
  ].map(([states, textContent]) => ({dataset:{states, state:states.split(' ')[0]}, textContent, hidden:false}));
  if (actionMode) {
    ['configure update investigate', 'investigate', 'checked', 'not_found', 'info'].forEach((actions, index) => {
      cards[index].dataset = {actions, state:actions.split(' ')[0]};
    });
  }
  const buttons = (actionMode ? ['configure', 'update', 'investigate', 'checked', 'not_found', 'info', 'all'] :
    ['action', 'review', 'complete', 'scope', 'info', 'all']).map(filter => ({
    dataset:{filter}, setAttribute(key,value) {this[key]=value;}
  }));
  const elements = {'record-search':{value:''}, 'result-count':{}, 'empty-results':{}};
  const missing = {hidden:false, open:false};
  const groups = cards.map(card => ({hidden:false, count:{textContent:''}, querySelectorAll:()=>[card],
    closest() {return card.dataset.state === 'scope' ? missing : null;},
    querySelector() {return this.count;}}));
  const details = [{open:false},{open:true}];
  const evidence = {tagName:'DETAILS',open:false,parentElement:details[0]};
  details[0].tagName = 'DETAILS';
  elements['item-0'] = {parentElement:evidence};
  const handlers = {};
  const context = vm.createContext({document:{
    getElementById(id) {return elements[id];},
    querySelector() {return cards[0];},
    querySelectorAll(selector) {
      if (selector === 'article[data-tool]') return cards;
      if (selector === 'button[data-filter]') return buttons;
      if (selector === '[data-result-group]') return groups;
      if (selector === 'details') return details;
      if (selector === '[hidden]') return [...cards, ...groups].filter(x => x.hidden);
      throw new Error(`Unexpected selector: ${selector}`);
    }
  }, window:{addEventListener(name, handler) {handlers[name]=handler;}}});
  vm.runInContext(fs.readFileSync(require.resolve('../report-ui.js'), 'utf8'), context);
  return {cards, buttons, elements, context, details, handlers, groups, missing, evidence};
}

test('first view shows the whole inventory instead of mixing pending states', () => {
  const ui = page();
  assert.deepEqual(ui.cards.filter(row => !row.hidden).map(row => row.dataset.state), ['action', 'review', 'complete', 'scope', 'info']);
  assert.equal(ui.elements['result-count'].textContent, '5 / 5ツール');
  assert.equal(ui.buttons.find(button => button.dataset.filter === 'all')['aria-pressed'], 'true');
});

test('category filters and search agree, including empty results and reset', () => {
  const ui = page();
  for (const group of ['action', 'review', 'complete', 'scope', 'info', 'all']) {
    vm.runInContext(`filterReports('${group}')`, ui.context);
    assert.equal(ui.cards.filter(row => !row.hidden).length, group === 'all' ? 5 : 1);
    assert.equal(ui.groups.filter(section => !section.hidden).length, group === 'all' ? 5 : 1);
  }
  ui.elements['record-search'].value = 'CURL';
  vm.runInContext("filterReports('all')", ui.context);
  assert.deepEqual(ui.cards.filter(row => !row.hidden).map(row => row.textContent), ['curl 検査用サイトへの接続をブロック']);
  assert.equal(ui.groups.find(section => !section.hidden).count.textContent, '1ツール');
  vm.runInContext("filterReports('review')", ui.context);
  assert.equal(ui.elements['empty-results'].hidden, false);
  ui.elements['record-search'].value = '';
  vm.runInContext("filterReports('all')", ui.context);
  assert.equal(ui.elements['empty-results'].hidden, true);
  assert.equal(ui.cards.filter(row => !row.hidden).length, 5);
});

test('a mixed tool belongs to its primary category and remains searchable in full', () => {
  const ui = page();
  ui.elements['record-search'].value = '/jdk/bin/java';
  vm.runInContext("filterReports('action')", ui.context);
  assert.deepEqual(ui.cards.filter(row => !row.hidden).map(row => row.dataset.state), ['action']);
  assert.equal(ui.elements['result-count'].textContent, '1 / 5ツール');
  assert.match(ui.cards[0].textContent, /要対応/);
  vm.runInContext("filterReports('review')", ui.context);
  assert.equal(ui.elements['empty-results'].hidden, false);
});

test('printing opens evidence and restores the reader’s previous disclosure state', () => {
  const ui = page();
  ui.handlers.beforeprint();
  assert.ok(ui.details.every(detail => detail.open));
  ui.handlers.afterprint();
  assert.deepEqual(ui.details.map(detail => detail.open), [false, true]);
});


test('category totals cover each tool exactly once, including mixed tools', () => {
  const ui = page();
  let total = 0;
  for (const group of ['action', 'review', 'complete', 'scope', 'info']) {
    vm.runInContext(`filterReports('${group}')`, ui.context);
    total += ui.cards.filter(x => !x.hidden).length;
  }
  assert.equal(total, ui.cards.length);
});

test('printing includes filtered-out tools and restores filter, search and counts', () => {
  const ui = page();
  ui.elements['record-search'].value = 'Java';
  vm.runInContext("filterReports('action')", ui.context);
  const hidden = ui.cards.map(x => x.hidden);
  ui.handlers.beforeprint();
  assert.ok(ui.cards.every(x => !x.hidden));
  assert.ok(ui.groups.every(x => !x.hidden));
  ui.handlers.afterprint();
  assert.deepEqual(ui.cards.map(x => x.hidden), hidden);
  assert.equal(ui.elements['record-search'].value, 'Java');
  assert.equal(ui.elements['result-count'].textContent, '1 / 5ツール');
  assert.equal(ui.buttons.find(x => x.dataset.filter === 'action')['aria-pressed'], 'true');
});

test('action filters include every required action of a mixed tool exactly once', () => {
  const ui = page(true);
  for (const action of ['configure', 'update']) {
    vm.runInContext(`filterReports('${action}')`, ui.context);
    assert.deepEqual(ui.cards.filter(x => !x.hidden), [ui.cards[0]]);
    assert.equal(ui.elements['result-count'].textContent, '1 / 5ツール');
  }
  vm.runInContext("filterReports('investigate')", ui.context);
  assert.deepEqual(ui.cards.filter(x => !x.hidden), ui.cards.slice(0, 2));
  assert.equal(ui.groups.filter(x => !x.hidden).length, 2);
});

test('multi-action search and printing retain the selected action', () => {
  const ui = page(true);
  ui.elements['record-search'].value = '/jdk/bin/java';
  vm.runInContext("filterReports('update')", ui.context);
  assert.equal(ui.cards[0].hidden, false);
  ui.handlers.beforeprint();
  assert.ok(ui.cards.every(x => !x.hidden));
  ui.handlers.afterprint();
  assert.equal(ui.cards[0].hidden, false);
  assert.equal(ui.elements['result-count'].textContent, '1 / 5ツール');
  assert.equal(ui.buttons.find(x => x.dataset.filter === 'update')['aria-pressed'], 'true');
});

test('an evidence link opens its enclosing disclosures without opening other tools', () => {
  const ui = page(true);
  vm.runInContext("revealRecord('item-0')", ui.context);
  assert.equal(ui.evidence.open, true);
  assert.equal(ui.details[0].open, true);
  assert.equal(ui.details[1].open, true);
  assert.doesNotThrow(() => vm.runInContext("revealRecord('missing-id')", ui.context));
});
