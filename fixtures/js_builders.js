// Fixture for JS/TS builder flow summaries. Each call below is a node the
// symbol-index enumerates; the binder must attach the summary edge to the
// exact value handles named in js_builders.index.json.
function demo(userInput, target, parts) {
  const lowered = userInput.toLowerCase();   // Receiver -> ReturnValue
  const merged  = Object.assign(target, userInput); // src -> target, and -> ret
  const joined  = parts.join(",");           // Receiver -> ReturnValue (+ sep arg)
  return { lowered, merged, joined };
}
