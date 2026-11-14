/**
 * Duplicate-key scan for JSON text that JSON.parse has already accepted. It walks the text once with a stack of
 * key sets (no regular expression is built from the input) and reports whether any object, at any depth, uses the
 * same key twice. Keys are compared after decoding, so "a" and "a" are the same key.
 */
export function hasDuplicateKeys(text) {
  const stack = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) return true;
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (c === '{') stack.push({ keys: new Set(), expectKey: true });
    else if (c === '[') stack.push({ keys: null, expectKey: false });
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top && top.keys) top.expectKey = true;
    }
    i++;
  }
  return false;
}
