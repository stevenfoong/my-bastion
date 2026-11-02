// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
/*
 * mybastion shared facet filters.
 *
 * A row of dropdown buttons, one per facet (Type, Folder, User, ...), each a
 * multi-select of the values present in the current rows with a count beside
 * each value. Values within a facet are OR'd, facets are AND'd, and counts
 * narrow as other facets are applied. Selections persist per page in
 * sessionStorage so a reload or a return to the page keeps them.
 *
 *   var f = rgFilters.create({
 *       mount:  document.getElementById('session-filters'),
 *       id:     'sessions',                       // storage key suffix
 *       facets: [
 *           { key: 'type',   label: 'Type',   value: function(r) { return r.session_type; },
 *             render: function(v) { return '<span class="type-badge type-' + v + '">' + v + '</span>'; } },
 *           { key: 'folder', label: 'Folder', value: function(r) { return r.folder; } }
 *       ],
 *       onChange: function() { render(); }
 *   });
 *   f.update(rows);            // recompute values and counts from the full row set
 *   var shown = f.apply(rows); // rows matching the current selection
 *
 * `value` may return a string, a number, null/undefined (shown as "(none)")
 * or an array of strings (the row matches if any selected value is in it).
 * `render` is optional and returns HTML for a value; the default escapes it.
 * Only one menu is open at a time; Escape and clicks outside close it.
 */
(function() {
    'use strict';

    var NONE = '\u0000none';
    var openMenu = null;

    function esc(s) {
        return String(s).replace(/[&<>"']/g, function(c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function el(tag, cls, html) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (html != null) e.innerHTML = html;
        return e;
    }
    function valuesOf(facet, row) {
        var v;
        try { v = facet.value(row); } catch (e) { v = null; }
        if (v == null || v === '') return [NONE];
        if (Object.prototype.toString.call(v) === '[object Array]') {
            var out = [];
            for (var i = 0; i < v.length; i++) if (v[i] != null && v[i] !== '') out.push(String(v[i]));
            return out.length ? out : [NONE];
        }
        return [String(v)];
    }
    function label(facet, v) {
        if (v === NONE) return facet.none || '(none)';
        return facet.render ? facet.render(v) : esc(v);
    }
    function plain(facet, v) {
        if (v === NONE) return facet.none || '(none)';
        return facet.text ? facet.text(v) : String(v);
    }

    function closeOpen() {
        if (!openMenu) return;
        openMenu.wrap.classList.remove('open');
        openMenu.btn.setAttribute('aria-expanded', 'false');
        openMenu.menu.hidden = true;
        openMenu = null;
    }
    document.addEventListener('mousedown', function(e) {
        if (openMenu && !openMenu.wrap.contains(e.target)) closeOpen();
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && openMenu) { closeOpen(); e.stopPropagation(); }
    });

    function create(opts) {
        var facets = opts.facets || [];
        var storageKey = 'mybastion_filters_' + (opts.id || 'page');
        var selected = {};   // facet key -> { value: true }
        var rows = [];
        var ui = {};         // facet key -> { wrap, btn, menu, list, find }

        try {
            var saved = JSON.parse(sessionStorage.getItem(storageKey) || '{}');
            facets.forEach(function(f) {
                var arr = saved[f.key];
                if (arr && arr.length) {
                    selected[f.key] = {};
                    arr.forEach(function(v) { selected[f.key][v] = true; });
                }
            });
        } catch (e) { selected = {}; }

        function persist() {
            var out = {};
            facets.forEach(function(f) {
                var s = selected[f.key];
                if (s) { var arr = Object.keys(s); if (arr.length) out[f.key] = arr; }
            });
            try {
                if (Object.keys(out).length) sessionStorage.setItem(storageKey, JSON.stringify(out));
                else sessionStorage.removeItem(storageKey);
            } catch (e) {}
        }
        function isActive(key) { return !!(selected[key] && Object.keys(selected[key]).length); }
        function anyActive() { return facets.some(function(f) { return isActive(f.key) && !(ui[f.key] && ui[f.key].wrap.hidden); }); }
        function matches(row, skipKey) {
            for (var i = 0; i < facets.length; i++) {
                var f = facets[i];
                if (f.key === skipKey || !isActive(f.key) || (ui[f.key] && ui[f.key].wrap.hidden)) continue;
                var vals = valuesOf(f, row), hit = false;
                for (var j = 0; j < vals.length; j++) if (selected[f.key][vals[j]]) { hit = true; break; }
                if (!hit) return false;
            }
            return true;
        }
        // Values and counts for one facet, narrowed by every other facet.
        function tally(facet) {
            var counts = {}, order = [];
            rows.forEach(function(r) {
                if (!matches(r, facet.key)) return;
                valuesOf(facet, r).forEach(function(v) {
                    if (!(v in counts)) { counts[v] = 0; order.push(v); }
                    counts[v]++;
                });
            });
            // Selected values no longer present stay listed (at 0) so they can be cleared.
            Object.keys(selected[facet.key] || {}).forEach(function(v) {
                if (!(v in counts)) { counts[v] = 0; order.push(v); }
            });
            order.sort(function(a, b) {
                if (a === NONE) return 1; if (b === NONE) return -1;
                if (facet.sort === 'count' && counts[a] !== counts[b]) return counts[b] - counts[a];
                return plain(facet, a).localeCompare(plain(facet, b), undefined, { numeric: true, sensitivity: 'base' });
            });
            return { counts: counts, order: order };
        }

        function renderButton(facet) {
            var u = ui[facet.key], s = selected[facet.key] || {}, keys = Object.keys(s);
            u.wrap.classList.toggle('active', keys.length > 0);
            var n = u.btn.querySelector('.rg-facet-n');
            if (keys.length === 1) { n.textContent = plain(facet, keys[0]); n.className = 'rg-facet-n one'; }
            else if (keys.length) { n.textContent = String(keys.length); n.className = 'rg-facet-n'; }
            else { n.textContent = ''; n.className = 'rg-facet-n'; }
            n.hidden = !keys.length;
            u.btn.title = keys.length ? facet.label + ': ' + keys.map(function(k) { return plain(facet, k); }).join(', ') : facet.label;
        }
        function renderList(facet) {
            var u = ui[facet.key], t = tally(facet), s = selected[facet.key] || {};
            var q = (u.find.value || '').toLowerCase();
            u.list.innerHTML = '';
            var shown = 0;
            t.order.forEach(function(v) {
                if (q && plain(facet, v).toLowerCase().indexOf(q) === -1) return;
                shown++;
                var opt = el('label', 'rg-facet-opt' + (t.counts[v] ? '' : ' zero'));
                var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!s[v]; cb.setAttribute('data-v', v);
                opt.appendChild(cb);
                opt.appendChild(el('span', 'rg-facet-val', label(facet, v)));
                opt.appendChild(el('span', 'rg-facet-count', String(t.counts[v])));
                u.list.appendChild(opt);
            });
            if (!shown) u.list.appendChild(el('div', 'rg-facet-empty', q ? 'No matches' : 'Nothing to filter'));
            u.find.parentNode.style.display = t.order.length > 7 || q ? '' : 'none';
        }
        function refreshAll() {
            facets.forEach(function(f) { renderButton(f); if (openMenu && openMenu.key === f.key) renderList(f); });
            ui.clear.hidden = !anyActive();
        }
        function change(facet, v, on) {
            if (!selected[facet.key]) selected[facet.key] = {};
            if (on) selected[facet.key][v] = true; else delete selected[facet.key][v];
            persist(); refreshAll();
            if (opts.onChange) opts.onChange();
        }
        function setAll(facet, on) {
            var t = tally(facet), q = (ui[facet.key].find.value || '').toLowerCase();
            if (!selected[facet.key]) selected[facet.key] = {};
            t.order.forEach(function(v) {
                if (q && plain(facet, v).toLowerCase().indexOf(q) === -1) return;
                if (on) selected[facet.key][v] = true; else delete selected[facet.key][v];
            });
            persist(); refreshAll();
            if (opts.onChange) opts.onChange();
        }
        function open(facet) {
            var u = ui[facet.key];
            if (openMenu && openMenu.key === facet.key) { closeOpen(); return; }
            closeOpen();
            u.find.value = '';
            renderList(facet);
            u.menu.hidden = false;
            u.wrap.classList.add('open');
            u.btn.setAttribute('aria-expanded', 'true');
            openMenu = { key: facet.key, wrap: u.wrap, btn: u.btn, menu: u.menu };
            // Keep the menu on screen when the button sits near the right edge.
            u.menu.classList.remove('right');
            var r = u.menu.getBoundingClientRect();
            if (r.right > window.innerWidth - 8) u.menu.classList.add('right');
            if (u.find.parentNode.style.display !== 'none') { try { u.find.focus(); } catch (e) {} }
        }

        var bar = el('div', 'rg-filters');
        if (opts.label) bar.appendChild(el('span', 'rg-filters-label', esc(opts.label)));
        facets.forEach(function(facet) {
            var wrap = el('div', 'rg-facet');
            var btn = el('button', 'rg-facet-btn', '<span class="rg-facet-label">' + esc(facet.label) + '</span><span class="rg-facet-n" hidden></span><span class="rg-facet-caret">&#9662;</span>');
            btn.type = 'button';
            btn.setAttribute('aria-haspopup', 'listbox');
            btn.setAttribute('aria-expanded', 'false');
            var menu = el('div', 'rg-facet-menu');
            menu.hidden = true;
            var tools = el('div', 'rg-facet-tools');
            var find = el('input'); find.type = 'search'; find.placeholder = 'Find…'; find.setAttribute('aria-label', 'Find ' + facet.label.toLowerCase());
            tools.appendChild(find);
            var all = el('button', 'rg-facet-tool', 'All'); all.type = 'button';
            var none = el('button', 'rg-facet-tool', 'None'); none.type = 'button';
            var toolsRow = el('div', 'rg-facet-tools-row');
            toolsRow.appendChild(tools); toolsRow.appendChild(all); toolsRow.appendChild(none);
            var list = el('div', 'rg-facet-list');
            menu.appendChild(toolsRow); menu.appendChild(list);
            wrap.appendChild(btn); wrap.appendChild(menu);
            bar.appendChild(wrap);
            ui[facet.key] = { wrap: wrap, btn: btn, menu: menu, list: list, find: find };

            btn.addEventListener('click', function() { open(facet); });
            find.addEventListener('input', function() { renderList(facet); });
            all.addEventListener('click', function() { setAll(facet, true); });
            none.addEventListener('click', function() { setAll(facet, false); });
            list.addEventListener('change', function(e) {
                var cb = e.target;
                if (cb && cb.type === 'checkbox') change(facet, cb.getAttribute('data-v'), cb.checked);
            });
        });
        var clear = el('button', 'rg-filters-clear', 'Clear filters');
        clear.type = 'button';
        clear.hidden = true;
        clear.addEventListener('click', function() {
            selected = {}; persist(); refreshAll();
            if (opts.onChange) opts.onChange();
        });
        bar.appendChild(clear);
        ui.clear = clear;
        if (opts.mount) opts.mount.appendChild(bar);

        var api = {
            element: bar,
            update: function(newRows) { rows = newRows || []; refreshAll(); return api; },
            apply: function(list) { return (list || rows).filter(function(r) { return matches(r, null); }); },
            active: anyActive,
            selected: function(key) { return Object.keys(selected[key] || {}); },
            // Hide a facet that has no meaning in the current view (its selection is kept but not applied).
            show: function(key, on) { if (ui[key]) ui[key].wrap.hidden = !on; return api; },
            clear: function() { selected = {}; persist(); refreshAll(); }
        };
        refreshAll();
        return api;
    }

    window.rgFilters = { create: create };
})();
