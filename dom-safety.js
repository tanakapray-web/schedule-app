/* Explicit DOM construction utilities. They do NOT retrofit unsafe legacy innerHTML sinks. */
(function (root) {
  'use strict';
  const fragments = new WeakMap(), events = new WeakMap();
  let sequence = 0;
  const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
  const allowedEvents = new Set(['click','change','input','keydown','keyup','submit','blur','focus']);
  const URL_ATTRIBUTES = new Set(['href','src','action','formaction','poster','xlink:href']);
  function jsonValue(value) {
    const json = JSON.stringify(value);
    if (json === undefined) throw new TypeError('Event arguments must be JSON-serializable values.');
    return json;
  }
  // Replace the COMPLETE argument including surrounding quotes. Never put this inside quotes.
  // Example: `<button onclick="openEdit(${DomSafety.eventArg(id)})">`.
  // It is a transitional helper, not permission to render unsanitized HTML or arbitrary handlers.
  function eventArg(value) {
    const serialized = JSON.stringify(jsonValue(value)).replace(/[<>&\u2028\u2029']/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0'));
    return escapeHTML('JSON.parse(' + serialized + ')');
  }
  function event(type, listener, options) {
    if (!allowedEvents.has(type) || typeof listener !== 'function') throw new TypeError('Unsupported event binding.');
    const token = Object.freeze({});
    events.set(token, { type, listener, options });
    return token;
  }
  function html(strings, ...values) {
    if (!Array.isArray(strings) || !Object.isFrozen(strings) || !Object.prototype.hasOwnProperty.call(strings, 'raw')) {
      throw new TypeError('html must be used as a tagged template with trusted static markup.');
    }
    const bindings = new Map();
    function interpolate(value) {
      if (Array.isArray(value)) return value.map(interpolate).join('');
      if (value && typeof value === 'object') {
        if (events.has(value)) {
          const marker = 'ds-' + (++sequence);
          bindings.set(marker, events.get(value));
          return ` data-ds-event-${marker}="" `;
        }
        if (fragments.has(value)) {
          const child = fragments.get(value);
          for (const [key, handler] of child.bindings) bindings.set(key, handler);
          return child.markup;
        }
      }
      return escapeHTML(value);
    }
    const markup = strings.reduce((out, part, index) => out + part + (index < values.length ? interpolate(values[index]) : ''), '');
    const token = Object.freeze({});
    fragments.set(token, { markup, bindings });
    return token;
  }
  function cleanURL(value, baseURI) {
    const normalized = String(value).trim();
    if (!normalized) return true;
    try {
      const url = new URL(normalized, baseURI);
      // No data/blob/javascript URLs from rendered strings, even for images.
      return ['https:', 'http:', 'mailto:', 'tel:'].includes(url.protocol);
    } catch { return false; }
  }
  function render(target, fragment, options = {}) {
    if (!target || !fragments.has(fragment)) throw new TypeError('render requires a target and a trusted tagged-template result.');
    const purifier = options.purifier || root.DOMPurify;
    if (!purifier || typeof purifier.sanitize !== 'function') throw new Error('DOMPurify must be bundled locally before rendering HTML.');
    const { markup, bindings } = fragments.get(fragment);
    const clean = purifier.sanitize(markup, {
      RETURN_DOM_FRAGMENT: true,
      USE_PROFILES: { html: true },
      ALLOW_DATA_ATTR: true,
      ALLOW_ARIA_ATTR: true,
      FORBID_TAGS: ['script','style','iframe','object','embed','link','meta','base','form'],
      FORBID_ATTR: ['srcdoc'],
      SANITIZE_DOM: true,
      SANITIZE_NAMED_PROPS: false
    });
    for (const element of clean.querySelectorAll('*')) {
      for (const attr of [...element.attributes]) {
        const name = attr.name.toLowerCase();
        if (name.startsWith('on')) element.removeAttribute(attr.name);
        if (name.startsWith('data-ds-event-')) {
          const key = name.slice('data-ds-event-'.length), binding = bindings.get(key);
          element.removeAttribute(attr.name);
          if (binding) element.addEventListener(binding.type, binding.listener, binding.options);
        }
        if (URL_ATTRIBUTES.has(name) && !cleanURL(attr.value, target.ownerDocument.baseURI)) element.removeAttribute(attr.name);
        if (name === 'style' && /(?:url\s*\(|expression\s*\(|@import|behavior\s*:|-moz-binding)/i.test(attr.value)) element.removeAttribute(attr.name);
      }
      if (element.tagName === 'A' && element.getAttribute('target') === '_blank') element.setAttribute('rel', 'noopener noreferrer');
    }
    target.replaceChildren(clean);
    return target;
  }
  function setText(target, value) { target.textContent = String(value ?? ''); return target; }
  const api = Object.freeze({ text: escapeHTML, attr: escapeHTML, eventArg, html, on: event, render, setText });
  root.DomSafety = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
