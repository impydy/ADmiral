/* Defence in depth for markup built from strings. The CSP says require-trusted-types-for 'script', so every
   innerHTML assignment passes through this default policy: even if a value was not escaped somewhere, the
   elements that could navigate the window (<meta http-equiv=refresh>), change the base URL, load or embed
   something are turned into plain text. ADmiral's own markup never uses them (inline SVG and <form> are fine:
   form-action 'none' blocks submitting). Loaded first, before any script writes markup. */
"use strict";
(() => {
  const BAD = /<(\/?)(meta|base|link|iframe|frame|frameset|object|embed|script|style|portal|fencedframe)(?=[\s/>]|$)/gi;
  const defuse = (s) => String(s).replace(BAD, "&lt;$1$2");
  if (typeof window !== "undefined") window.admiralDefuse = defuse;
  if (typeof trustedTypes !== "undefined" && trustedTypes.createPolicy) {
    trustedTypes.createPolicy("default", { createHTML: defuse });
  }
})();
