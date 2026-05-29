(() => {
  const wrapSelection = (ta, before, after, placeholder) => {
    const start = ta.selectionStart ?? 0;
    const end = ta.selectionEnd ?? 0;
    const selected = ta.value.slice(start, end) || placeholder;
    const insert = `${before}${selected}${after}`;
    ta.setRangeText(insert, start, end, 'select');
    if (start === end) {
      ta.setSelectionRange(start + before.length, start + before.length + selected.length);
    }
  };

  const prefixLines = (ta, prefix, placeholder) => {
    const start = ta.selectionStart ?? 0;
    const end = ta.selectionEnd ?? 0;
    const raw = ta.value.slice(start, end);
    const text = raw || placeholder;
    const lines = text.split('\n').map((line, idx) => {
      const p = typeof prefix === 'function' ? prefix(idx) : prefix;
      return `${p}${line}`;
    });
    const prefixBlock = start > 0 && ta.value[start - 1] !== '\n' ? '\n' : '';
    const insert = `${prefixBlock}${lines.join('\n')}`;
    ta.setRangeText(insert, start, end, 'end');
  };

  const insertBlock = (ta, block, selectOffsetStart, selectOffsetEnd) => {
    const start = ta.selectionStart ?? 0;
    const end = ta.selectionEnd ?? 0;
    const needNl = start > 0 && ta.value[start - 1] !== '\n' ? '\n\n' : '';
    const insert = `${needNl}${block}`;
    ta.setRangeText(insert, start, end, 'end');
    if (typeof selectOffsetStart === 'number' && typeof selectOffsetEnd === 'number') {
      const base = start + needNl.length;
      ta.setSelectionRange(base + selectOffsetStart, base + selectOffsetEnd);
    }
  };

  const applyAction = (ta, action) => {
    switch (action) {
      case 'h2':
        prefixLines(ta, '## ', 'Überschrift');
        break;
      case 'h3':
        prefixLines(ta, '### ', 'Unterüberschrift');
        break;
      case 'bold':
        wrapSelection(ta, '**', '**', 'Fett');
        break;
      case 'italic':
        wrapSelection(ta, '*', '*', 'Kursiv');
        break;
      case 'ul':
        prefixLines(ta, '- ', 'Listeneintrag');
        break;
      case 'ol':
        prefixLines(ta, (i) => `${i + 1}. `, 'Listeneintrag');
        break;
      case 'table':
        insertBlock(
          ta,
          '| Spalte 1 | Spalte 2 |\n| --- | --- |\n| Wert 1 | Wert 2 |\n'
        );
        break;
      case 'anchor':
        insertBlock(ta, '<a id="abschnitt"></a>\n## ', 7, 16);
        break;
      default:
        return;
    }
    ta.focus();
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  };

  document.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-md-action]');
    if (!btn) return;
    const toolbar = btn.closest('[data-md-toolbar]');
    if (!toolbar) return;

    const targetId = toolbar.getAttribute('data-md-toolbar');
    const ta = targetId
      ? document.getElementById(targetId)
      : toolbar.parentElement?.querySelector('textarea');
    if (!ta) return;

    event.preventDefault();
    applyAction(ta, btn.getAttribute('data-md-action'));
  });
})();
