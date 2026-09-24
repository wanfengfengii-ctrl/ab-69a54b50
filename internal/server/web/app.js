'use strict';

const MIN_CARDS = 4;
const MAX_CARDS = 8;
const MAX_SHARE_BYTES = 128;

const cardsEl = document.getElementById('cards');
const formEl = document.getElementById('reconstruct-form');
const thresholdEl = document.getElementById('threshold');
const addBtn = document.getElementById('add-card');
const submitBtn = document.getElementById('submit-btn');
const resultEl = document.getElementById('result');
const formErrorsEl = document.getElementById('form-errors');

/* ---------- 卡片行 ---------- */

function rows() {
  return Array.from(cardsEl.querySelectorAll('.card-row'));
}

function makeRow() {
  const row = document.createElement('div');
  row.className = 'card-row';
  row.innerHTML = `
    <div class="card-head">
      <span class="card-label"></span>
      <button type="button" class="remove-card" title="移除该卡" aria-label="移除该卡">×</button>
    </div>
    <div class="card-fields">
      <input class="card-id" type="number" min="1" max="255" step="1" placeholder="编号 1–255" required>
      <input class="card-share" type="text" placeholder="等长十六进制份额，如 9f3a04…" spellcheck="false" autocomplete="off" required>
    </div>
    <p class="field-error" data-role="id-error" hidden></p>
    <p class="field-error" data-role="share-error" hidden></p>`;
  row.querySelector('.remove-card').addEventListener('click', () => {
    if (rows().length <= MIN_CARDS) return;
    row.remove();
    reindex();
    clearResult();
  });
  row.querySelectorAll('input').forEach((inp) => inp.addEventListener('input', clearResult));
  return row;
}

function addRow() {
  if (rows().length >= MAX_CARDS) return;
  cardsEl.appendChild(makeRow());
  reindex();
  clearResult();
}

// 重新编号，使错误定位 data-error-for 与提交数组下标一致。
function reindex() {
  const list = rows();
  list.forEach((row, i) => {
    row.querySelector('.card-label').textContent = `卡 ${i + 1}`;
    row.querySelector('[data-role="id-error"]').dataset.errorFor = `cards[${i}].id`;
    row.querySelector('[data-role="share-error"]').dataset.errorFor = `cards[${i}].share`;
    row.querySelector('.remove-card').disabled = list.length <= MIN_CARDS;
  });
  addBtn.disabled = list.length >= MAX_CARDS;
}

/* ---------- 结果与错误展示 ---------- */

// 提交新数据或修改任何输入后，旧结论立即失效，不得保留。
function clearResult() {
  resultEl.hidden = true;
  resultEl.className = 'result';
  resultEl.innerHTML = '';
}

function clearErrors() {
  formErrorsEl.hidden = true;
  formErrorsEl.innerHTML = '';
  document.querySelectorAll('.field-error').forEach((el) => {
    el.hidden = true;
    el.textContent = '';
  });
  document.querySelectorAll('.invalid').forEach((el) => el.classList.remove('invalid'));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

// 将服务返回的可定位错误标注到对应输入框，无法定位的汇入总列表。
function showErrors(errors) {
  const general = [];
  for (const err of errors) {
    const slot = err.field
      ? document.querySelector(`[data-error-for="${CSS.escape(err.field)}"]`)
      : null;
    if (slot) {
      slot.textContent = err.message;
      slot.hidden = false;
      const row = slot.closest('.card-row');
      if (row) {
        row.querySelector(err.field.endsWith('.id') ? '.card-id' : '.card-share').classList.add('invalid');
      } else if (err.field === 'threshold') {
        thresholdEl.classList.add('invalid');
      }
    } else {
      general.push(err.field ? `${err.field}：${err.message}` : err.message);
    }
  }
  if (general.length > 0) {
    formErrorsEl.innerHTML = general.map((m) => `<li>${escapeHtml(m)}</li>`).join('');
    formErrorsEl.hidden = false;
  }
}

function formatKey(hex) {
  return hex.replace(/../g, '$& ').trim().toUpperCase();
}

function showResult(body) {
  let cls = 'bad';
  let html = '';
  if (body.status === 'CONSISTENT') {
    cls = 'ok';
    html = `<h2>CONSISTENT</h2>
      <p>全部份额一致。设备恢复密钥（${body.key.length / 2} 字节）：</p>
      <p class="key">${formatKey(body.key)}</p>`;
  } else if (body.status === 'RECOVERED') {
    cls = 'warn';
    html = `<h2>RECOVERED</h2>
      <p>已剔除问题卡（编号 <strong>${Number(body.excludedCardId)}</strong>），其余份额一致。设备恢复密钥（${body.key.length / 2} 字节）：</p>
      <p class="key">${formatKey(body.key)}</p>`;
  } else if (body.status === 'CONFLICT') {
    cls = 'bad';
    html = `<h2>CONFLICT</h2>
      <p>份额相互矛盾，无法确定唯一的恢复密钥。出于安全考虑，本次<strong>不输出任何密钥</strong>；请逐卡核对份额后重新录入。</p>`;
  } else {
    html = `<h2>未知响应</h2><p>${escapeHtml(JSON.stringify(body))}</p>`;
  }
  resultEl.className = `result ${cls}`;
  resultEl.innerHTML = html;
  resultEl.hidden = false;
}

/* ---------- 采集与本地预校验（服务端仍会复核） ---------- */

function gather() {
  return {
    threshold: Number(thresholdEl.value),
    cards: rows().map((row) => ({
      id: Number(row.querySelector('.card-id').value),
      share: row.querySelector('.card-share').value.trim(),
    })),
  };
}

function clientValidate(data) {
  const errs = [];
  const push = (field, message) => errs.push({ field, message });
  const n = data.cards.length;

  if (n < MIN_CARDS || n > MAX_CARDS) {
    push('cards', `卡片数量须在 ${MIN_CARDS}–${MAX_CARDS} 张之间`);
  }
  if (!Number.isInteger(data.threshold)) {
    push('threshold', '门限值必须是整数');
  } else if (data.threshold < 2) {
    push('threshold', '门限值至少为 2');
  } else if (data.threshold > n) {
    push('threshold', `门限值不能大于卡片数量（当前 ${n} 张）`);
  }

  const seen = new Map();
  let baseLen = -1;
  data.cards.forEach((c, i) => {
    if (!Number.isInteger(c.id)) {
      push(`cards[${i}].id`, '编号必须是整数');
    } else if (c.id < 1 || c.id > 255) {
      push(`cards[${i}].id`, '编号必须在 1–255 之间（非零）');
    } else if (seen.has(c.id)) {
      push(`cards[${i}].id`, `编号 ${c.id} 与其他卡重复`);
      push(`cards[${seen.get(c.id)}].id`, `编号 ${c.id} 与其他卡重复`);
    } else {
      seen.set(c.id, i);
    }

    const s = c.share;
    if (!s) {
      push(`cards[${i}].share`, '份额必填');
    } else if (s.length % 2 !== 0) {
      push(`cards[${i}].share`, '份额必须为偶数个十六进制字符');
    } else if (!/^[0-9a-fA-F]+$/.test(s)) {
      push(`cards[${i}].share`, '份额包含非十六进制字符');
    } else {
      const bytes = s.length / 2;
      if (bytes > MAX_SHARE_BYTES) {
        push(`cards[${i}].share`, `份额过长：最多 ${MAX_SHARE_BYTES} 字节`);
      }
      if (baseLen < 0) {
        baseLen = bytes;
      } else if (bytes !== baseLen) {
        push(`cards[${i}].share`, `份额长度需一致：首张 ${baseLen} 字节，本卡 ${bytes} 字节`);
      }
    }
  });
  return errs;
}

/* ---------- 提交 ---------- */

formEl.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearResult(); // 旧结论不得保留
  clearErrors();

  const data = gather();
  const localErrors = clientValidate(data);
  if (localErrors.length > 0) {
    showErrors(localErrors);
    return;
  }

  submitBtn.disabled = true;
  try {
    const resp = await fetch('/api/recovery/reconstruct', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const body = await resp.json().catch(() => null);
    if (!resp.ok) {
      showErrors(body && Array.isArray(body.errors)
        ? body.errors
        : [{ field: '', message: `请求失败（HTTP ${resp.status}）` }]);
      return;
    }
    showResult(body);
  } catch {
    showErrors([{ field: '', message: '网络错误：无法连接服务，请稍后重试' }]);
  } finally {
    submitBtn.disabled = false;
  }
});

thresholdEl.addEventListener('input', clearResult);
addBtn.addEventListener('click', addRow);

/* ---------- 初始化 ---------- */

for (let i = 0; i < MIN_CARDS; i += 1) {
  cardsEl.appendChild(makeRow());
}
reindex();
