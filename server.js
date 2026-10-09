// @bun
// src/runtime.js
import { join as join5, resolve } from "path";
import { homedir } from "os";
import { rm as rm2 } from "fs/promises";

// src/io.js
import { mkdir, open, rename, lstat, readFile } from "fs/promises";
import { dirname } from "path";
import { randomBytes, createHash } from "crypto";
var random = () => randomBytes(32).toString("base64url");
var digest = (text) => createHash("sha256").update(text).digest("hex");
var sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted)
    return reject(new Error("\u041E\u043F\u0435\u0440\u0430\u0446\u0438\u044F \u043E\u0442\u043C\u0435\u043D\u0435\u043D\u0430"));
  const timer = setTimeout(done, ms);
  function done() {
    signal?.removeEventListener("abort", cancel);
    resolve();
  }
  function cancel() {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
    reject(new Error("\u041E\u043F\u0435\u0440\u0430\u0446\u0438\u044F \u043E\u0442\u043C\u0435\u043D\u0435\u043D\u0430"));
  }
  signal?.addEventListener("abort", cancel, { once: true });
});
async function exists(path) {
  try {
    return await lstat(path);
  } catch (e) {
    if (e.code === "ENOENT")
      return null;
    throw e;
  }
}
async function atomicWrite(path, text) {
  await mkdir(dirname(path), { recursive: true, mode: 448 });
  if ((await exists(path))?.isSymbolicLink())
    throw new Error("\u041E\u0442\u043A\u0430\u0437 \u0437\u0430\u043F\u0438\u0441\u0438 \u0447\u0435\u0440\u0435\u0437 \u0441\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443");
  const temp = `${path}.${random()}.tmp`;
  const handle = await open(temp, "wx", 384);
  try {
    await handle.writeFile(text);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temp, path);
}
async function readJSON(path, fallback = null) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT")
      return fallback;
    throw e;
  }
}
function trustedURL(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0430\u0434\u0440\u0435\u0441 \u0441\u0435\u0440\u0432\u0435\u0440\u0430");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) {
    throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u0434\u043E\u043B\u0436\u0435\u043D \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u044C HTTPS (HTTP \u0440\u0430\u0437\u0440\u0435\u0448\u0451\u043D \u0442\u043E\u043B\u044C\u043A\u043E \u043D\u0430 loopback)");
  }
  return url.href.replace(/\/$/, "");
}
function serial() {
  let tail = Promise.resolve();
  return (fn) => {
    const next = tail.then(fn, fn);
    tail = next.catch(() => {});
    return next;
  };
}
var escapeHTML = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// src/api.js
class Unauthorized extends Error {
  constructor() {
    super("\u0421\u0435\u0441\u0441\u0438\u044F \u0438\u0441\u0442\u0435\u043A\u043B\u0430. \u0412\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 /login");
  }
}

class CorporateAPI {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }
  async request(path, { token, method = "GET", body, etag, signal } = {}) {
    const response = await fetch(`${this.baseURL}${path}`, {
      method,
      redirect: "error",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(1e4)]) : AbortSignal.timeout(1e4),
      headers: { ...token ? { Authorization: `Bearer ${token}` } : {}, ...body ? { "Content-Type": "application/json" } : {}, ...etag ? { "If-None-Match": etag } : {} },
      body: body ? JSON.stringify(body) : undefined
    });
    if (response.status === 401)
      throw new Unauthorized;
    if (response.status === 304)
      return { unchanged: true, etag };
    if (!response.ok)
      throw new Error(`\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0435\u0440\u0432\u0435\u0440: HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > 1048576)
      throw new Error("\u041E\u0442\u0432\u0435\u0442 \u0441\u0435\u0440\u0432\u0435\u0440\u0430 \u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0431\u043E\u043B\u044C\u0448\u043E\u0439");
    return { data: text ? JSON.parse(text) : null, etag: response.headers.get("etag") };
  }
}

// node_modules/jsonc-parser/lib/esm/impl/scanner.js
function createScanner(text, ignoreTrivia = false) {
  const len = text.length;
  let pos = 0, value = "", tokenOffset = 0, token = 16, lineNumber = 0, lineStartOffset = 0, tokenLineStartOffset = 0, prevTokenLineStartOffset = 0, scanError = 0;
  function scanHexDigits(count, exact) {
    let digits = 0;
    let value2 = 0;
    while (digits < count || !exact) {
      let ch = text.charCodeAt(pos);
      if (ch >= 48 && ch <= 57) {
        value2 = value2 * 16 + ch - 48;
      } else if (ch >= 65 && ch <= 70) {
        value2 = value2 * 16 + ch - 65 + 10;
      } else if (ch >= 97 && ch <= 102) {
        value2 = value2 * 16 + ch - 97 + 10;
      } else {
        break;
      }
      pos++;
      digits++;
    }
    if (digits < count) {
      value2 = -1;
    }
    return value2;
  }
  function setPosition(newPosition) {
    pos = newPosition;
    value = "";
    tokenOffset = 0;
    token = 16;
    scanError = 0;
  }
  function scanNumber() {
    let start = pos;
    if (text.charCodeAt(pos) === 48) {
      pos++;
    } else {
      pos++;
      while (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
      }
    }
    if (pos < text.length && text.charCodeAt(pos) === 46) {
      pos++;
      if (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
        while (pos < text.length && isDigit(text.charCodeAt(pos))) {
          pos++;
        }
      } else {
        scanError = 3;
        return text.substring(start, pos);
      }
    }
    let end = pos;
    if (pos < text.length && (text.charCodeAt(pos) === 69 || text.charCodeAt(pos) === 101)) {
      pos++;
      if (pos < text.length && text.charCodeAt(pos) === 43 || text.charCodeAt(pos) === 45) {
        pos++;
      }
      if (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
        while (pos < text.length && isDigit(text.charCodeAt(pos))) {
          pos++;
        }
        end = pos;
      } else {
        scanError = 3;
      }
    }
    return text.substring(start, end);
  }
  function scanString() {
    let result = "", start = pos;
    while (true) {
      if (pos >= len) {
        result += text.substring(start, pos);
        scanError = 2;
        break;
      }
      const ch = text.charCodeAt(pos);
      if (ch === 34) {
        result += text.substring(start, pos);
        pos++;
        break;
      }
      if (ch === 92) {
        result += text.substring(start, pos);
        pos++;
        if (pos >= len) {
          scanError = 2;
          break;
        }
        const ch2 = text.charCodeAt(pos++);
        switch (ch2) {
          case 34:
            result += '"';
            break;
          case 92:
            result += "\\";
            break;
          case 47:
            result += "/";
            break;
          case 98:
            result += "\b";
            break;
          case 102:
            result += "\f";
            break;
          case 110:
            result += `
`;
            break;
          case 114:
            result += "\r";
            break;
          case 116:
            result += "\t";
            break;
          case 117:
            const ch3 = scanHexDigits(4, true);
            if (ch3 >= 0) {
              result += String.fromCharCode(ch3);
            } else {
              scanError = 4;
            }
            break;
          default:
            scanError = 5;
        }
        start = pos;
        continue;
      }
      if (ch >= 0 && ch <= 31) {
        if (isLineBreak(ch)) {
          result += text.substring(start, pos);
          scanError = 2;
          break;
        } else {
          scanError = 6;
        }
      }
      pos++;
    }
    return result;
  }
  function scanNext() {
    value = "";
    scanError = 0;
    tokenOffset = pos;
    lineStartOffset = lineNumber;
    prevTokenLineStartOffset = tokenLineStartOffset;
    if (pos >= len) {
      tokenOffset = len;
      return token = 17;
    }
    let code = text.charCodeAt(pos);
    if (isWhiteSpace(code)) {
      do {
        pos++;
        value += String.fromCharCode(code);
        code = text.charCodeAt(pos);
      } while (isWhiteSpace(code));
      return token = 15;
    }
    if (isLineBreak(code)) {
      pos++;
      value += String.fromCharCode(code);
      if (code === 13 && text.charCodeAt(pos) === 10) {
        pos++;
        value += `
`;
      }
      lineNumber++;
      tokenLineStartOffset = pos;
      return token = 14;
    }
    switch (code) {
      case 123:
        pos++;
        return token = 1;
      case 125:
        pos++;
        return token = 2;
      case 91:
        pos++;
        return token = 3;
      case 93:
        pos++;
        return token = 4;
      case 58:
        pos++;
        return token = 6;
      case 44:
        pos++;
        return token = 5;
      case 34:
        pos++;
        value = scanString();
        return token = 10;
      case 47:
        const start = pos - 1;
        if (text.charCodeAt(pos + 1) === 47) {
          pos += 2;
          while (pos < len) {
            if (isLineBreak(text.charCodeAt(pos))) {
              break;
            }
            pos++;
          }
          value = text.substring(start, pos);
          return token = 12;
        }
        if (text.charCodeAt(pos + 1) === 42) {
          pos += 2;
          const safeLength = len - 1;
          let commentClosed = false;
          while (pos < safeLength) {
            const ch = text.charCodeAt(pos);
            if (ch === 42 && text.charCodeAt(pos + 1) === 47) {
              pos += 2;
              commentClosed = true;
              break;
            }
            pos++;
            if (isLineBreak(ch)) {
              if (ch === 13 && text.charCodeAt(pos) === 10) {
                pos++;
              }
              lineNumber++;
              tokenLineStartOffset = pos;
            }
          }
          if (!commentClosed) {
            pos++;
            scanError = 1;
          }
          value = text.substring(start, pos);
          return token = 13;
        }
        value += String.fromCharCode(code);
        pos++;
        return token = 16;
      case 45:
        value += String.fromCharCode(code);
        pos++;
        if (pos === len || !isDigit(text.charCodeAt(pos))) {
          return token = 16;
        }
      case 48:
      case 49:
      case 50:
      case 51:
      case 52:
      case 53:
      case 54:
      case 55:
      case 56:
      case 57:
        value += scanNumber();
        return token = 11;
      default:
        while (pos < len && isUnknownContentCharacter(code)) {
          pos++;
          code = text.charCodeAt(pos);
        }
        if (tokenOffset !== pos) {
          value = text.substring(tokenOffset, pos);
          switch (value) {
            case "true":
              return token = 8;
            case "false":
              return token = 9;
            case "null":
              return token = 7;
          }
          return token = 16;
        }
        value += String.fromCharCode(code);
        pos++;
        return token = 16;
    }
  }
  function isUnknownContentCharacter(code) {
    if (isWhiteSpace(code) || isLineBreak(code)) {
      return false;
    }
    switch (code) {
      case 125:
      case 93:
      case 123:
      case 91:
      case 34:
      case 58:
      case 44:
      case 47:
        return false;
    }
    return true;
  }
  function scanNextNonTrivia() {
    let result;
    do {
      result = scanNext();
    } while (result >= 12 && result <= 15);
    return result;
  }
  return {
    setPosition,
    getPosition: () => pos,
    scan: ignoreTrivia ? scanNextNonTrivia : scanNext,
    getToken: () => token,
    getTokenValue: () => value,
    getTokenOffset: () => tokenOffset,
    getTokenLength: () => pos - tokenOffset,
    getTokenStartLine: () => lineStartOffset,
    getTokenStartCharacter: () => tokenOffset - prevTokenLineStartOffset,
    getTokenError: () => scanError
  };
}
function isWhiteSpace(ch) {
  return ch === 32 || ch === 9;
}
function isLineBreak(ch) {
  return ch === 10 || ch === 13;
}
function isDigit(ch) {
  return ch >= 48 && ch <= 57;
}
var CharacterCodes;
(function(CharacterCodes2) {
  CharacterCodes2[CharacterCodes2["lineFeed"] = 10] = "lineFeed";
  CharacterCodes2[CharacterCodes2["carriageReturn"] = 13] = "carriageReturn";
  CharacterCodes2[CharacterCodes2["space"] = 32] = "space";
  CharacterCodes2[CharacterCodes2["_0"] = 48] = "_0";
  CharacterCodes2[CharacterCodes2["_1"] = 49] = "_1";
  CharacterCodes2[CharacterCodes2["_2"] = 50] = "_2";
  CharacterCodes2[CharacterCodes2["_3"] = 51] = "_3";
  CharacterCodes2[CharacterCodes2["_4"] = 52] = "_4";
  CharacterCodes2[CharacterCodes2["_5"] = 53] = "_5";
  CharacterCodes2[CharacterCodes2["_6"] = 54] = "_6";
  CharacterCodes2[CharacterCodes2["_7"] = 55] = "_7";
  CharacterCodes2[CharacterCodes2["_8"] = 56] = "_8";
  CharacterCodes2[CharacterCodes2["_9"] = 57] = "_9";
  CharacterCodes2[CharacterCodes2["a"] = 97] = "a";
  CharacterCodes2[CharacterCodes2["b"] = 98] = "b";
  CharacterCodes2[CharacterCodes2["c"] = 99] = "c";
  CharacterCodes2[CharacterCodes2["d"] = 100] = "d";
  CharacterCodes2[CharacterCodes2["e"] = 101] = "e";
  CharacterCodes2[CharacterCodes2["f"] = 102] = "f";
  CharacterCodes2[CharacterCodes2["g"] = 103] = "g";
  CharacterCodes2[CharacterCodes2["h"] = 104] = "h";
  CharacterCodes2[CharacterCodes2["i"] = 105] = "i";
  CharacterCodes2[CharacterCodes2["j"] = 106] = "j";
  CharacterCodes2[CharacterCodes2["k"] = 107] = "k";
  CharacterCodes2[CharacterCodes2["l"] = 108] = "l";
  CharacterCodes2[CharacterCodes2["m"] = 109] = "m";
  CharacterCodes2[CharacterCodes2["n"] = 110] = "n";
  CharacterCodes2[CharacterCodes2["o"] = 111] = "o";
  CharacterCodes2[CharacterCodes2["p"] = 112] = "p";
  CharacterCodes2[CharacterCodes2["q"] = 113] = "q";
  CharacterCodes2[CharacterCodes2["r"] = 114] = "r";
  CharacterCodes2[CharacterCodes2["s"] = 115] = "s";
  CharacterCodes2[CharacterCodes2["t"] = 116] = "t";
  CharacterCodes2[CharacterCodes2["u"] = 117] = "u";
  CharacterCodes2[CharacterCodes2["v"] = 118] = "v";
  CharacterCodes2[CharacterCodes2["w"] = 119] = "w";
  CharacterCodes2[CharacterCodes2["x"] = 120] = "x";
  CharacterCodes2[CharacterCodes2["y"] = 121] = "y";
  CharacterCodes2[CharacterCodes2["z"] = 122] = "z";
  CharacterCodes2[CharacterCodes2["A"] = 65] = "A";
  CharacterCodes2[CharacterCodes2["B"] = 66] = "B";
  CharacterCodes2[CharacterCodes2["C"] = 67] = "C";
  CharacterCodes2[CharacterCodes2["D"] = 68] = "D";
  CharacterCodes2[CharacterCodes2["E"] = 69] = "E";
  CharacterCodes2[CharacterCodes2["F"] = 70] = "F";
  CharacterCodes2[CharacterCodes2["G"] = 71] = "G";
  CharacterCodes2[CharacterCodes2["H"] = 72] = "H";
  CharacterCodes2[CharacterCodes2["I"] = 73] = "I";
  CharacterCodes2[CharacterCodes2["J"] = 74] = "J";
  CharacterCodes2[CharacterCodes2["K"] = 75] = "K";
  CharacterCodes2[CharacterCodes2["L"] = 76] = "L";
  CharacterCodes2[CharacterCodes2["M"] = 77] = "M";
  CharacterCodes2[CharacterCodes2["N"] = 78] = "N";
  CharacterCodes2[CharacterCodes2["O"] = 79] = "O";
  CharacterCodes2[CharacterCodes2["P"] = 80] = "P";
  CharacterCodes2[CharacterCodes2["Q"] = 81] = "Q";
  CharacterCodes2[CharacterCodes2["R"] = 82] = "R";
  CharacterCodes2[CharacterCodes2["S"] = 83] = "S";
  CharacterCodes2[CharacterCodes2["T"] = 84] = "T";
  CharacterCodes2[CharacterCodes2["U"] = 85] = "U";
  CharacterCodes2[CharacterCodes2["V"] = 86] = "V";
  CharacterCodes2[CharacterCodes2["W"] = 87] = "W";
  CharacterCodes2[CharacterCodes2["X"] = 88] = "X";
  CharacterCodes2[CharacterCodes2["Y"] = 89] = "Y";
  CharacterCodes2[CharacterCodes2["Z"] = 90] = "Z";
  CharacterCodes2[CharacterCodes2["asterisk"] = 42] = "asterisk";
  CharacterCodes2[CharacterCodes2["backslash"] = 92] = "backslash";
  CharacterCodes2[CharacterCodes2["closeBrace"] = 125] = "closeBrace";
  CharacterCodes2[CharacterCodes2["closeBracket"] = 93] = "closeBracket";
  CharacterCodes2[CharacterCodes2["colon"] = 58] = "colon";
  CharacterCodes2[CharacterCodes2["comma"] = 44] = "comma";
  CharacterCodes2[CharacterCodes2["dot"] = 46] = "dot";
  CharacterCodes2[CharacterCodes2["doubleQuote"] = 34] = "doubleQuote";
  CharacterCodes2[CharacterCodes2["minus"] = 45] = "minus";
  CharacterCodes2[CharacterCodes2["openBrace"] = 123] = "openBrace";
  CharacterCodes2[CharacterCodes2["openBracket"] = 91] = "openBracket";
  CharacterCodes2[CharacterCodes2["plus"] = 43] = "plus";
  CharacterCodes2[CharacterCodes2["slash"] = 47] = "slash";
  CharacterCodes2[CharacterCodes2["formFeed"] = 12] = "formFeed";
  CharacterCodes2[CharacterCodes2["tab"] = 9] = "tab";
})(CharacterCodes || (CharacterCodes = {}));

// node_modules/jsonc-parser/lib/esm/impl/string-intern.js
var cachedSpaces = new Array(20).fill(0).map((_, index) => {
  return " ".repeat(index);
});
var maxCachedValues = 200;
var cachedBreakLinesWithSpaces = {
  " ": {
    "\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return `
` + " ".repeat(index);
    }),
    "\r": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r" + " ".repeat(index);
    }),
    "\r\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return `\r
` + " ".repeat(index);
    })
  },
  "\t": {
    "\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return `
` + "\t".repeat(index);
    }),
    "\r": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r" + "\t".repeat(index);
    }),
    "\r\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return `\r
` + "\t".repeat(index);
    })
  }
};
var supportedEols = [`
`, "\r", `\r
`];

// node_modules/jsonc-parser/lib/esm/impl/format.js
function format(documentText, range, options) {
  let initialIndentLevel;
  let formatText;
  let formatTextStart;
  let rangeStart;
  let rangeEnd;
  if (range) {
    rangeStart = range.offset;
    rangeEnd = rangeStart + range.length;
    formatTextStart = rangeStart;
    while (formatTextStart > 0 && !isEOL(documentText, formatTextStart - 1)) {
      formatTextStart--;
    }
    let endOffset = rangeEnd;
    while (endOffset < documentText.length && !isEOL(documentText, endOffset)) {
      endOffset++;
    }
    formatText = documentText.substring(formatTextStart, endOffset);
    initialIndentLevel = computeIndentLevel(formatText, options);
  } else {
    formatText = documentText;
    initialIndentLevel = 0;
    formatTextStart = 0;
    rangeStart = 0;
    rangeEnd = documentText.length;
  }
  const eol = getEOL(options, documentText);
  const eolFastPathSupported = supportedEols.includes(eol);
  let numberLineBreaks = 0;
  let indentLevel = 0;
  let indentValue;
  if (options.insertSpaces) {
    indentValue = cachedSpaces[options.tabSize || 4] ?? repeat(cachedSpaces[1], options.tabSize || 4);
  } else {
    indentValue = "\t";
  }
  const indentType = indentValue === "\t" ? "\t" : " ";
  let scanner = createScanner(formatText, false);
  let hasError = false;
  function newLinesAndIndent() {
    if (numberLineBreaks > 1) {
      return repeat(eol, numberLineBreaks) + repeat(indentValue, initialIndentLevel + indentLevel);
    }
    const amountOfSpaces = indentValue.length * (initialIndentLevel + indentLevel);
    if (!eolFastPathSupported || amountOfSpaces > cachedBreakLinesWithSpaces[indentType][eol].length) {
      return eol + repeat(indentValue, initialIndentLevel + indentLevel);
    }
    if (amountOfSpaces <= 0) {
      return eol;
    }
    return cachedBreakLinesWithSpaces[indentType][eol][amountOfSpaces];
  }
  function scanNext() {
    let token = scanner.scan();
    numberLineBreaks = 0;
    while (token === 15 || token === 14) {
      if (token === 14 && options.keepLines) {
        numberLineBreaks += 1;
      } else if (token === 14) {
        numberLineBreaks = 1;
      }
      token = scanner.scan();
    }
    hasError = token === 16 || scanner.getTokenError() !== 0;
    return token;
  }
  const editOperations = [];
  function addEdit(text, startOffset, endOffset) {
    if (!hasError && (!range || startOffset < rangeEnd && endOffset > rangeStart) && documentText.substring(startOffset, endOffset) !== text) {
      editOperations.push({ offset: startOffset, length: endOffset - startOffset, content: text });
    }
  }
  let firstToken = scanNext();
  if (options.keepLines && numberLineBreaks > 0) {
    addEdit(repeat(eol, numberLineBreaks), 0, 0);
  }
  if (firstToken !== 17) {
    let firstTokenStart = scanner.getTokenOffset() + formatTextStart;
    let initialIndent = indentValue.length * initialIndentLevel < 20 && options.insertSpaces ? cachedSpaces[indentValue.length * initialIndentLevel] : repeat(indentValue, initialIndentLevel);
    addEdit(initialIndent, formatTextStart, firstTokenStart);
  }
  while (firstToken !== 17) {
    let firstTokenEnd = scanner.getTokenOffset() + scanner.getTokenLength() + formatTextStart;
    let secondToken = scanNext();
    let replaceContent = "";
    let needsLineBreak = false;
    while (numberLineBreaks === 0 && (secondToken === 12 || secondToken === 13)) {
      let commentTokenStart = scanner.getTokenOffset() + formatTextStart;
      addEdit(cachedSpaces[1], firstTokenEnd, commentTokenStart);
      firstTokenEnd = scanner.getTokenOffset() + scanner.getTokenLength() + formatTextStart;
      needsLineBreak = secondToken === 12;
      replaceContent = needsLineBreak ? newLinesAndIndent() : "";
      secondToken = scanNext();
    }
    if (secondToken === 2) {
      if (firstToken !== 1) {
        indentLevel--;
      }
      if (options.keepLines && numberLineBreaks > 0 || !options.keepLines && firstToken !== 1) {
        replaceContent = newLinesAndIndent();
      } else if (options.keepLines) {
        replaceContent = cachedSpaces[1];
      }
    } else if (secondToken === 4) {
      if (firstToken !== 3) {
        indentLevel--;
      }
      if (options.keepLines && numberLineBreaks > 0 || !options.keepLines && firstToken !== 3) {
        replaceContent = newLinesAndIndent();
      } else if (options.keepLines) {
        replaceContent = cachedSpaces[1];
      }
    } else {
      switch (firstToken) {
        case 3:
        case 1:
          indentLevel++;
          if (options.keepLines && numberLineBreaks > 0 || !options.keepLines) {
            replaceContent = newLinesAndIndent();
          } else {
            replaceContent = cachedSpaces[1];
          }
          break;
        case 5:
          if (options.keepLines && numberLineBreaks > 0 || !options.keepLines) {
            replaceContent = newLinesAndIndent();
          } else {
            replaceContent = cachedSpaces[1];
          }
          break;
        case 12:
          replaceContent = newLinesAndIndent();
          break;
        case 13:
          if (numberLineBreaks > 0) {
            replaceContent = newLinesAndIndent();
          } else if (!needsLineBreak) {
            replaceContent = cachedSpaces[1];
          }
          break;
        case 6:
          if (options.keepLines && numberLineBreaks > 0) {
            replaceContent = newLinesAndIndent();
          } else if (!needsLineBreak) {
            replaceContent = cachedSpaces[1];
          }
          break;
        case 10:
          if (options.keepLines && numberLineBreaks > 0) {
            replaceContent = newLinesAndIndent();
          } else if (secondToken === 6 && !needsLineBreak) {
            replaceContent = "";
          }
          break;
        case 7:
        case 8:
        case 9:
        case 11:
        case 2:
        case 4:
          if (options.keepLines && numberLineBreaks > 0) {
            replaceContent = newLinesAndIndent();
          } else {
            if ((secondToken === 12 || secondToken === 13) && !needsLineBreak) {
              replaceContent = cachedSpaces[1];
            } else if (secondToken !== 5 && secondToken !== 17) {
              hasError = true;
            }
          }
          break;
        case 16:
          hasError = true;
          break;
      }
      if (numberLineBreaks > 0 && (secondToken === 12 || secondToken === 13)) {
        replaceContent = newLinesAndIndent();
      }
    }
    if (secondToken === 17) {
      if (options.keepLines && numberLineBreaks > 0) {
        replaceContent = newLinesAndIndent();
      } else {
        replaceContent = options.insertFinalNewline ? eol : "";
      }
    }
    const secondTokenStart = scanner.getTokenOffset() + formatTextStart;
    addEdit(replaceContent, firstTokenEnd, secondTokenStart);
    firstToken = secondToken;
  }
  return editOperations;
}
function repeat(s, count) {
  let result = "";
  for (let i = 0;i < count; i++) {
    result += s;
  }
  return result;
}
function computeIndentLevel(content, options) {
  let i = 0;
  let nChars = 0;
  const tabSize = options.tabSize || 4;
  while (i < content.length) {
    let ch = content.charAt(i);
    if (ch === cachedSpaces[1]) {
      nChars++;
    } else if (ch === "\t") {
      nChars += tabSize;
    } else {
      break;
    }
    i++;
  }
  return Math.floor(nChars / tabSize);
}
function getEOL(options, text) {
  for (let i = 0;i < text.length; i++) {
    const ch = text.charAt(i);
    if (ch === "\r") {
      if (i + 1 < text.length && text.charAt(i + 1) === `
`) {
        return `\r
`;
      }
      return "\r";
    } else if (ch === `
`) {
      return `
`;
    }
  }
  return options && options.eol || `
`;
}
function isEOL(text, offset) {
  return `\r
`.indexOf(text.charAt(offset)) !== -1;
}

// node_modules/jsonc-parser/lib/esm/impl/parser.js
var ParseOptions;
(function(ParseOptions2) {
  ParseOptions2.DEFAULT = {
    allowTrailingComma: false
  };
})(ParseOptions || (ParseOptions = {}));
function parse(text, errors = [], options = ParseOptions.DEFAULT) {
  let currentProperty = null;
  let currentParent = [];
  const previousParents = [];
  function onValue(value) {
    if (Array.isArray(currentParent)) {
      currentParent.push(value);
    } else if (currentProperty !== null) {
      currentParent[currentProperty] = value;
    }
  }
  const visitor = {
    onObjectBegin: () => {
      const object = {};
      onValue(object);
      previousParents.push(currentParent);
      currentParent = object;
      currentProperty = null;
    },
    onObjectProperty: (name) => {
      currentProperty = name;
    },
    onObjectEnd: () => {
      currentParent = previousParents.pop();
    },
    onArrayBegin: () => {
      const array = [];
      onValue(array);
      previousParents.push(currentParent);
      currentParent = array;
      currentProperty = null;
    },
    onArrayEnd: () => {
      currentParent = previousParents.pop();
    },
    onLiteralValue: onValue,
    onError: (error, offset, length) => {
      errors.push({ error, offset, length });
    }
  };
  visit(text, visitor, options);
  return currentParent[0];
}
function parseTree(text, errors = [], options = ParseOptions.DEFAULT) {
  let currentParent = { type: "array", offset: -1, length: -1, children: [], parent: undefined };
  function ensurePropertyComplete(endOffset) {
    if (currentParent.type === "property") {
      currentParent.length = endOffset - currentParent.offset;
      currentParent = currentParent.parent;
    }
  }
  function onValue(valueNode) {
    currentParent.children.push(valueNode);
    return valueNode;
  }
  const visitor = {
    onObjectBegin: (offset) => {
      currentParent = onValue({ type: "object", offset, length: -1, parent: currentParent, children: [] });
    },
    onObjectProperty: (name, offset, length) => {
      currentParent = onValue({ type: "property", offset, length: -1, parent: currentParent, children: [] });
      currentParent.children.push({ type: "string", value: name, offset, length, parent: currentParent });
    },
    onObjectEnd: (offset, length) => {
      ensurePropertyComplete(offset + length);
      currentParent.length = offset + length - currentParent.offset;
      currentParent = currentParent.parent;
      ensurePropertyComplete(offset + length);
    },
    onArrayBegin: (offset, length) => {
      currentParent = onValue({ type: "array", offset, length: -1, parent: currentParent, children: [] });
    },
    onArrayEnd: (offset, length) => {
      currentParent.length = offset + length - currentParent.offset;
      currentParent = currentParent.parent;
      ensurePropertyComplete(offset + length);
    },
    onLiteralValue: (value, offset, length) => {
      onValue({ type: getNodeType(value), offset, length, parent: currentParent, value });
      ensurePropertyComplete(offset + length);
    },
    onSeparator: (sep, offset, length) => {
      if (currentParent.type === "property") {
        if (sep === ":") {
          currentParent.colonOffset = offset;
        } else if (sep === ",") {
          ensurePropertyComplete(offset);
        }
      }
    },
    onError: (error, offset, length) => {
      errors.push({ error, offset, length });
    }
  };
  visit(text, visitor, options);
  const result = currentParent.children[0];
  if (result) {
    delete result.parent;
  }
  return result;
}
function findNodeAtLocation(root, path) {
  if (!root) {
    return;
  }
  let node = root;
  for (let segment of path) {
    if (typeof segment === "string") {
      if (node.type !== "object" || !Array.isArray(node.children)) {
        return;
      }
      let found = false;
      for (const propertyNode of node.children) {
        if (Array.isArray(propertyNode.children) && propertyNode.children[0].value === segment && propertyNode.children.length === 2) {
          node = propertyNode.children[1];
          found = true;
          break;
        }
      }
      if (!found) {
        return;
      }
    } else {
      const index = segment;
      if (node.type !== "array" || index < 0 || !Array.isArray(node.children) || index >= node.children.length) {
        return;
      }
      node = node.children[index];
    }
  }
  return node;
}
function visit(text, visitor, options = ParseOptions.DEFAULT) {
  const _scanner = createScanner(text, false);
  const _jsonPath = [];
  let suppressedCallbacks = 0;
  function toNoArgVisit(visitFunction) {
    return visitFunction ? () => suppressedCallbacks === 0 && visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter()) : () => true;
  }
  function toOneArgVisit(visitFunction) {
    return visitFunction ? (arg) => suppressedCallbacks === 0 && visitFunction(arg, _scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter()) : () => true;
  }
  function toOneArgVisitWithPath(visitFunction) {
    return visitFunction ? (arg) => suppressedCallbacks === 0 && visitFunction(arg, _scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter(), () => _jsonPath.slice()) : () => true;
  }
  function toBeginVisit(visitFunction) {
    return visitFunction ? () => {
      if (suppressedCallbacks > 0) {
        suppressedCallbacks++;
      } else {
        let cbReturn = visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter(), () => _jsonPath.slice());
        if (cbReturn === false) {
          suppressedCallbacks = 1;
        }
      }
    } : () => true;
  }
  function toEndVisit(visitFunction) {
    return visitFunction ? () => {
      if (suppressedCallbacks > 0) {
        suppressedCallbacks--;
      }
      if (suppressedCallbacks === 0) {
        visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter());
      }
    } : () => true;
  }
  const onObjectBegin = toBeginVisit(visitor.onObjectBegin), onObjectProperty = toOneArgVisitWithPath(visitor.onObjectProperty), onObjectEnd = toEndVisit(visitor.onObjectEnd), onArrayBegin = toBeginVisit(visitor.onArrayBegin), onArrayEnd = toEndVisit(visitor.onArrayEnd), onLiteralValue = toOneArgVisitWithPath(visitor.onLiteralValue), onSeparator = toOneArgVisit(visitor.onSeparator), onComment = toNoArgVisit(visitor.onComment), onError = toOneArgVisit(visitor.onError);
  const disallowComments = options && options.disallowComments;
  const allowTrailingComma = options && options.allowTrailingComma;
  function scanNext() {
    while (true) {
      const token = _scanner.scan();
      switch (_scanner.getTokenError()) {
        case 4:
          handleError(14);
          break;
        case 5:
          handleError(15);
          break;
        case 3:
          handleError(13);
          break;
        case 1:
          if (!disallowComments) {
            handleError(11);
          }
          break;
        case 2:
          handleError(12);
          break;
        case 6:
          handleError(16);
          break;
      }
      switch (token) {
        case 12:
        case 13:
          if (disallowComments) {
            handleError(10);
          } else {
            onComment();
          }
          break;
        case 16:
          handleError(1);
          break;
        case 15:
        case 14:
          break;
        default:
          return token;
      }
    }
  }
  function handleError(error, skipUntilAfter = [], skipUntil = []) {
    onError(error);
    if (skipUntilAfter.length + skipUntil.length > 0) {
      let token = _scanner.getToken();
      while (token !== 17) {
        if (skipUntilAfter.indexOf(token) !== -1) {
          scanNext();
          break;
        } else if (skipUntil.indexOf(token) !== -1) {
          break;
        }
        token = scanNext();
      }
    }
  }
  function parseString(isValue) {
    const value = _scanner.getTokenValue();
    if (isValue) {
      onLiteralValue(value);
    } else {
      onObjectProperty(value);
      _jsonPath.push(value);
    }
    scanNext();
    return true;
  }
  function parseLiteral() {
    switch (_scanner.getToken()) {
      case 11:
        const tokenValue = _scanner.getTokenValue();
        let value = Number(tokenValue);
        if (isNaN(value)) {
          handleError(2);
          value = 0;
        }
        onLiteralValue(value);
        break;
      case 7:
        onLiteralValue(null);
        break;
      case 8:
        onLiteralValue(true);
        break;
      case 9:
        onLiteralValue(false);
        break;
      default:
        return false;
    }
    scanNext();
    return true;
  }
  function parseProperty() {
    if (_scanner.getToken() !== 10) {
      handleError(3, [], [2, 5]);
      return false;
    }
    parseString(false);
    if (_scanner.getToken() === 6) {
      onSeparator(":");
      scanNext();
      if (!parseValue()) {
        handleError(4, [], [2, 5]);
      }
    } else {
      handleError(5, [], [2, 5]);
    }
    _jsonPath.pop();
    return true;
  }
  function parseObject() {
    onObjectBegin();
    scanNext();
    let needsComma = false;
    while (_scanner.getToken() !== 2 && _scanner.getToken() !== 17) {
      if (_scanner.getToken() === 5) {
        if (!needsComma) {
          handleError(4, [], []);
        }
        onSeparator(",");
        scanNext();
        if (_scanner.getToken() === 2 && allowTrailingComma) {
          break;
        }
      } else if (needsComma) {
        handleError(6, [], []);
      }
      if (!parseProperty()) {
        handleError(4, [], [2, 5]);
      }
      needsComma = true;
    }
    onObjectEnd();
    if (_scanner.getToken() !== 2) {
      handleError(7, [2], []);
    } else {
      scanNext();
    }
    return true;
  }
  function parseArray() {
    onArrayBegin();
    scanNext();
    let isFirstElement = true;
    let needsComma = false;
    while (_scanner.getToken() !== 4 && _scanner.getToken() !== 17) {
      if (_scanner.getToken() === 5) {
        if (!needsComma) {
          handleError(4, [], []);
        }
        onSeparator(",");
        scanNext();
        if (_scanner.getToken() === 4 && allowTrailingComma) {
          break;
        }
      } else if (needsComma) {
        handleError(6, [], []);
      }
      if (isFirstElement) {
        _jsonPath.push(0);
        isFirstElement = false;
      } else {
        _jsonPath[_jsonPath.length - 1]++;
      }
      if (!parseValue()) {
        handleError(4, [], [4, 5]);
      }
      needsComma = true;
    }
    onArrayEnd();
    if (!isFirstElement) {
      _jsonPath.pop();
    }
    if (_scanner.getToken() !== 4) {
      handleError(8, [4], []);
    } else {
      scanNext();
    }
    return true;
  }
  function parseValue() {
    switch (_scanner.getToken()) {
      case 3:
        return parseArray();
      case 1:
        return parseObject();
      case 10:
        return parseString(true);
      default:
        return parseLiteral();
    }
  }
  scanNext();
  if (_scanner.getToken() === 17) {
    if (options.allowEmptyContent) {
      return true;
    }
    handleError(4, [], []);
    return false;
  }
  if (!parseValue()) {
    handleError(4, [], []);
    return false;
  }
  if (_scanner.getToken() !== 17) {
    handleError(9, [], []);
  }
  return true;
}
function getNodeType(value) {
  switch (typeof value) {
    case "boolean":
      return "boolean";
    case "number":
      return "number";
    case "string":
      return "string";
    case "object": {
      if (!value) {
        return "null";
      } else if (Array.isArray(value)) {
        return "array";
      }
      return "object";
    }
    default:
      return "null";
  }
}

// node_modules/jsonc-parser/lib/esm/impl/edit.js
function setProperty(text, originalPath, value, options) {
  const path = originalPath.slice();
  const errors = [];
  const root = parseTree(text, errors);
  let parent = undefined;
  let lastSegment = undefined;
  while (path.length > 0) {
    lastSegment = path.pop();
    parent = findNodeAtLocation(root, path);
    if (parent === undefined && value !== undefined) {
      if (typeof lastSegment === "string") {
        value = { [lastSegment]: value };
      } else {
        value = [value];
      }
    } else {
      break;
    }
  }
  if (!parent) {
    if (value === undefined) {
      throw new Error("Can not delete in empty document");
    }
    return withFormatting(text, { offset: root ? root.offset : 0, length: root ? root.length : 0, content: JSON.stringify(value) }, options);
  } else if (parent.type === "object" && typeof lastSegment === "string" && Array.isArray(parent.children)) {
    const existing = findNodeAtLocation(parent, [lastSegment]);
    if (existing !== undefined) {
      if (value === undefined) {
        if (!existing.parent) {
          throw new Error("Malformed AST");
        }
        const propertyIndex = parent.children.indexOf(existing.parent);
        let removeBegin;
        let removeEnd = existing.parent.offset + existing.parent.length;
        if (propertyIndex > 0) {
          let previous = parent.children[propertyIndex - 1];
          removeBegin = previous.offset + previous.length;
        } else {
          removeBegin = parent.offset + 1;
          if (parent.children.length > 1) {
            let next = parent.children[1];
            removeEnd = next.offset;
          }
        }
        return withFormatting(text, { offset: removeBegin, length: removeEnd - removeBegin, content: "" }, options);
      } else {
        return withFormatting(text, { offset: existing.offset, length: existing.length, content: JSON.stringify(value) }, options);
      }
    } else {
      if (value === undefined) {
        return [];
      }
      const newProperty = `${JSON.stringify(lastSegment)}: ${JSON.stringify(value)}`;
      const index = options.getInsertionIndex ? options.getInsertionIndex(parent.children.map((p) => p.children[0].value)) : parent.children.length;
      let edit;
      if (index > 0) {
        let previous = parent.children[index - 1];
        edit = { offset: previous.offset + previous.length, length: 0, content: "," + newProperty };
      } else if (parent.children.length === 0) {
        edit = { offset: parent.offset + 1, length: 0, content: newProperty };
      } else {
        edit = { offset: parent.offset + 1, length: 0, content: newProperty + "," };
      }
      return withFormatting(text, edit, options);
    }
  } else if (parent.type === "array" && typeof lastSegment === "number" && Array.isArray(parent.children)) {
    const insertIndex = lastSegment;
    if (insertIndex === -1) {
      const newProperty = `${JSON.stringify(value)}`;
      let edit;
      if (parent.children.length === 0) {
        edit = { offset: parent.offset + 1, length: 0, content: newProperty };
      } else {
        const previous = parent.children[parent.children.length - 1];
        edit = { offset: previous.offset + previous.length, length: 0, content: "," + newProperty };
      }
      return withFormatting(text, edit, options);
    } else if (value === undefined && parent.children.length >= 0) {
      const removalIndex = lastSegment;
      const toRemove = parent.children[removalIndex];
      let edit;
      if (parent.children.length === 1) {
        edit = { offset: parent.offset + 1, length: parent.length - 2, content: "" };
      } else if (parent.children.length - 1 === removalIndex) {
        let previous = parent.children[removalIndex - 1];
        let offset = previous.offset + previous.length;
        let parentEndOffset = parent.offset + parent.length;
        edit = { offset, length: parentEndOffset - 2 - offset, content: "" };
      } else {
        edit = { offset: toRemove.offset, length: parent.children[removalIndex + 1].offset - toRemove.offset, content: "" };
      }
      return withFormatting(text, edit, options);
    } else if (value !== undefined) {
      let edit;
      const newProperty = `${JSON.stringify(value)}`;
      if (!options.isArrayInsertion && parent.children.length > lastSegment) {
        const toModify = parent.children[lastSegment];
        edit = { offset: toModify.offset, length: toModify.length, content: newProperty };
      } else if (parent.children.length === 0 || lastSegment === 0) {
        edit = { offset: parent.offset + 1, length: 0, content: parent.children.length === 0 ? newProperty : newProperty + "," };
      } else {
        const index = lastSegment > parent.children.length ? parent.children.length : lastSegment;
        const previous = parent.children[index - 1];
        edit = { offset: previous.offset + previous.length, length: 0, content: "," + newProperty };
      }
      return withFormatting(text, edit, options);
    } else {
      throw new Error(`Can not ${value === undefined ? "remove" : options.isArrayInsertion ? "insert" : "modify"} Array index ${insertIndex} as length is not sufficient`);
    }
  } else {
    throw new Error(`Can not add ${typeof lastSegment !== "number" ? "index" : "property"} to parent of type ${parent.type}`);
  }
}
function withFormatting(text, edit, options) {
  if (!options.formattingOptions) {
    return [edit];
  }
  let newText = applyEdit(text, edit);
  let begin = edit.offset;
  let end = edit.offset + edit.content.length;
  if (edit.length === 0 || edit.content.length === 0) {
    while (begin > 0 && !isEOL(newText, begin - 1)) {
      begin--;
    }
    while (end < newText.length && !isEOL(newText, end)) {
      end++;
    }
  }
  const edits = format(newText, { offset: begin, length: end - begin }, { ...options.formattingOptions, keepLines: false });
  for (let i = edits.length - 1;i >= 0; i--) {
    const edit2 = edits[i];
    newText = applyEdit(newText, edit2);
    begin = Math.min(begin, edit2.offset);
    end = Math.max(end, edit2.offset + edit2.length);
    end += edit2.content.length - edit2.length;
  }
  const editLength = text.length - (newText.length - end) - begin;
  return [{ offset: begin, length: editLength, content: newText.substring(begin, end) }];
}
function applyEdit(text, edit) {
  return text.substring(0, edit.offset) + edit.content + text.substring(edit.offset + edit.length);
}

// node_modules/jsonc-parser/lib/esm/main.js
var ScanError;
(function(ScanError2) {
  ScanError2[ScanError2["None"] = 0] = "None";
  ScanError2[ScanError2["UnexpectedEndOfComment"] = 1] = "UnexpectedEndOfComment";
  ScanError2[ScanError2["UnexpectedEndOfString"] = 2] = "UnexpectedEndOfString";
  ScanError2[ScanError2["UnexpectedEndOfNumber"] = 3] = "UnexpectedEndOfNumber";
  ScanError2[ScanError2["InvalidUnicode"] = 4] = "InvalidUnicode";
  ScanError2[ScanError2["InvalidEscapeCharacter"] = 5] = "InvalidEscapeCharacter";
  ScanError2[ScanError2["InvalidCharacter"] = 6] = "InvalidCharacter";
})(ScanError || (ScanError = {}));
var SyntaxKind;
(function(SyntaxKind2) {
  SyntaxKind2[SyntaxKind2["OpenBraceToken"] = 1] = "OpenBraceToken";
  SyntaxKind2[SyntaxKind2["CloseBraceToken"] = 2] = "CloseBraceToken";
  SyntaxKind2[SyntaxKind2["OpenBracketToken"] = 3] = "OpenBracketToken";
  SyntaxKind2[SyntaxKind2["CloseBracketToken"] = 4] = "CloseBracketToken";
  SyntaxKind2[SyntaxKind2["CommaToken"] = 5] = "CommaToken";
  SyntaxKind2[SyntaxKind2["ColonToken"] = 6] = "ColonToken";
  SyntaxKind2[SyntaxKind2["NullKeyword"] = 7] = "NullKeyword";
  SyntaxKind2[SyntaxKind2["TrueKeyword"] = 8] = "TrueKeyword";
  SyntaxKind2[SyntaxKind2["FalseKeyword"] = 9] = "FalseKeyword";
  SyntaxKind2[SyntaxKind2["StringLiteral"] = 10] = "StringLiteral";
  SyntaxKind2[SyntaxKind2["NumericLiteral"] = 11] = "NumericLiteral";
  SyntaxKind2[SyntaxKind2["LineCommentTrivia"] = 12] = "LineCommentTrivia";
  SyntaxKind2[SyntaxKind2["BlockCommentTrivia"] = 13] = "BlockCommentTrivia";
  SyntaxKind2[SyntaxKind2["LineBreakTrivia"] = 14] = "LineBreakTrivia";
  SyntaxKind2[SyntaxKind2["Trivia"] = 15] = "Trivia";
  SyntaxKind2[SyntaxKind2["Unknown"] = 16] = "Unknown";
  SyntaxKind2[SyntaxKind2["EOF"] = 17] = "EOF";
})(SyntaxKind || (SyntaxKind = {}));
var parse2 = parse;
var ParseErrorCode;
(function(ParseErrorCode2) {
  ParseErrorCode2[ParseErrorCode2["InvalidSymbol"] = 1] = "InvalidSymbol";
  ParseErrorCode2[ParseErrorCode2["InvalidNumberFormat"] = 2] = "InvalidNumberFormat";
  ParseErrorCode2[ParseErrorCode2["PropertyNameExpected"] = 3] = "PropertyNameExpected";
  ParseErrorCode2[ParseErrorCode2["ValueExpected"] = 4] = "ValueExpected";
  ParseErrorCode2[ParseErrorCode2["ColonExpected"] = 5] = "ColonExpected";
  ParseErrorCode2[ParseErrorCode2["CommaExpected"] = 6] = "CommaExpected";
  ParseErrorCode2[ParseErrorCode2["CloseBraceExpected"] = 7] = "CloseBraceExpected";
  ParseErrorCode2[ParseErrorCode2["CloseBracketExpected"] = 8] = "CloseBracketExpected";
  ParseErrorCode2[ParseErrorCode2["EndOfFileExpected"] = 9] = "EndOfFileExpected";
  ParseErrorCode2[ParseErrorCode2["InvalidCommentToken"] = 10] = "InvalidCommentToken";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfComment"] = 11] = "UnexpectedEndOfComment";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfString"] = 12] = "UnexpectedEndOfString";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfNumber"] = 13] = "UnexpectedEndOfNumber";
  ParseErrorCode2[ParseErrorCode2["InvalidUnicode"] = 14] = "InvalidUnicode";
  ParseErrorCode2[ParseErrorCode2["InvalidEscapeCharacter"] = 15] = "InvalidEscapeCharacter";
  ParseErrorCode2[ParseErrorCode2["InvalidCharacter"] = 16] = "InvalidCharacter";
})(ParseErrorCode || (ParseErrorCode = {}));
function modify(text, path, value, options) {
  return setProperty(text, path, value, options);
}
function applyEdits(text, edits) {
  let sortedEdits = edits.slice(0).sort((a, b) => {
    const diff = a.offset - b.offset;
    if (diff === 0) {
      return a.length - b.length;
    }
    return diff;
  });
  let lastModifiedOffset = text.length;
  for (let i = sortedEdits.length - 1;i >= 0; i--) {
    let e = sortedEdits[i];
    if (e.offset + e.length <= lastModifiedOffset) {
      text = applyEdit(text, e);
    } else {
      throw new Error("Overlapping edit");
    }
    lastModifiedOffset = e.offset;
  }
  return text;
}

// src/config.js
import { readFile as readFile2 } from "fs/promises";
import { join as join2 } from "path";

// src/mcp.js
import { rm } from "fs/promises";
import { join } from "path";
import { createHash as createHash2 } from "crypto";
var idPattern = /^[a-z][a-z0-9_-]{0,39}$/;
var text = (value, max = 200) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
var validToken = (value) => text(value, 512) && !/[\r\n]/.test(value);
function validateMCPCatalog(data, serverURL) {
  if (!data || !Array.isArray(data.servers) || data.servers.length > 30)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043A\u0430\u0442\u0430\u043B\u043E\u0433 MCP");
  const ids = new Set;
  return data.servers.map((entry) => {
    if (!entry || !idPattern.test(entry.id) || ids.has(entry.id) || !text(entry.name, 100) || !text(entry.description) || entry.auth !== "personal_token")
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C MCP");
    ids.add(entry.id);
    const url = trustedURL(entry.url);
    if (new URL(url).origin !== new URL(serverURL).origin || new URL(url).pathname !== `/mcp/${entry.id}`)
      throw new Error("MCP \u0434\u043E\u043B\u0436\u0435\u043D \u043D\u0430\u0445\u043E\u0434\u0438\u0442\u044C\u0441\u044F \u043D\u0430 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u043E\u043C \u0441\u0435\u0440\u0432\u0435\u0440\u0435");
    return { id: entry.id, name: entry.name, description: entry.description, url, auth: entry.auth };
  });
}
function validateSelection(ids, catalog) {
  if (!Array.isArray(ids) || ids.length > catalog.length || new Set(ids).size !== ids.length || ids.some((id) => !catalog.some((entry) => entry.id === id)))
    throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D MCP \u0432\u043D\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0433\u043E \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430");
  return ids;
}
function mcpEnvName(stateDir, id) {
  if (!idPattern.test(id))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 ID MCP");
  const profile = createHash2("sha256").update(stateDir).digest("hex").slice(0, 12).toUpperCase();
  return `CORP_MCP_${profile}_${Buffer.from(id).toString("hex").toUpperCase()}_TOKEN`;
}
function configFor(stateDir, entry) {
  const env = mcpEnvName(stateDir, entry.id);
  return { name: `corp_${entry.id}`, config: {
    type: "remote",
    url: entry.url,
    oauth: false,
    headers: { Authorization: `Bearer {env:${env}}` }
  } };
}
function readMCPState(stateDir, catalog) {
  return catalog.filter((entry) => validToken(process.env[mcpEnvName(stateDir, entry.id)])).map((entry) => configFor(stateDir, entry));
}
function saveMCPSelection(stateDir, ids, catalog, tokens) {
  validateSelection(ids, catalog);
  if (!(tokens instanceof Map) || [...tokens.keys()].some((id) => !ids.includes(id)))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043D\u0430\u0431\u043E\u0440 \u0442\u043E\u043A\u0435\u043D\u043E\u0432 MCP");
  for (const id of ids) {
    const value = tokens.has(id) ? tokens.get(id) : process.env[mcpEnvName(stateDir, id)];
    if (!validToken(value))
      throw new Error(`\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u043B\u0438\u0447\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D MCP: ${id}`);
  }
  for (const id of ids)
    if (tokens.has(id))
      process.env[mcpEnvName(stateDir, id)] = tokens.get(id);
  for (const entry of catalog)
    if (!ids.includes(entry.id))
      delete process.env[mcpEnvName(stateDir, entry.id)];
  return ids.map((id) => configFor(stateDir, catalog.find((entry) => entry.id === id)));
}
function clearMCPEnv(stateDir) {
  const profile = createHash2("sha256").update(stateDir).digest("hex").slice(0, 12).toUpperCase();
  for (const key of Object.keys(process.env))
    if (key.startsWith(`CORP_MCP_${profile}_`) && key.endsWith("_TOKEN"))
      delete process.env[key];
}
async function clearMCP(stateDir) {
  clearMCPEnv(stateDir);
  await Promise.all([
    rm(join(stateDir, "mcp-selection.json"), { force: true }),
    rm(join(stateDir, "mcp-tokens"), { force: true, recursive: true })
  ]);
}

// src/config.js
function object(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}
function exactKeys(value, keys) {
  return object(value) && Object.keys(value).every((key) => keys.includes(key));
}
var safeLabel = (value) => typeof value === "string" && value.length > 0 && value.length <= 100 && !/\{(?:file|env):/.test(value);
function validateConfig(envelope, serverURL) {
  if (!exactKeys(envelope, ["revision", "config"]) || !Number.isSafeInteger(envelope.revision) || envelope.revision < 1)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0430\u044F \u0432\u0435\u0440\u0441\u0438\u044F \u043A\u043E\u043D\u0444\u0438\u0433\u0430");
  const config = envelope.config;
  if (!exactKeys(config, ["providers"]) || !exactKeys(config.providers, ["corporate"]))
    throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u043C\u043E\u0436\u0435\u0442 \u043C\u0435\u043D\u044F\u0442\u044C \u0442\u043E\u043B\u044C\u043A\u043E providers.corporate");
  const provider = config.providers.corporate;
  if (!exactKeys(provider, ["name", "settings", "models"]) || !safeLabel(provider.name))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440");
  if (!exactKeys(provider.settings, ["baseURL"]) || provider.settings.baseURL !== `${serverURL}/v1`)
    throw new Error("\u041D\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0451\u043D \u0430\u0434\u0440\u0435\u0441 inference API");
  if (!object(provider.models) || !Object.keys(provider.models).length || Object.keys(provider.models).length > 20)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0441\u043F\u0438\u0441\u043E\u043A \u043C\u043E\u0434\u0435\u043B\u0435\u0439");
  for (const [id, model] of Object.entries(provider.models)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(id) || !exactKeys(model, ["name", "limit"]) || !safeLabel(model.name))
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0430\u044F \u043C\u043E\u0434\u0435\u043B\u044C");
    if (!exactKeys(model.limit, ["context", "output"]) || !Number.isInteger(model.limit.context) || !Number.isInteger(model.limit.output) || model.limit.output < 1 || model.limit.output > model.limit.context || model.limit.context > 2000000)
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0435 \u043B\u0438\u043C\u0438\u0442\u044B \u043C\u043E\u0434\u0435\u043B\u0438");
  }
  return JSON.parse(JSON.stringify(envelope));
}
function parseConfig(text2) {
  const errors = [];
  const value = parse2(text2, errors, { allowTrailingComma: true });
  if (errors.length || !object(value))
    throw new Error("opencode.jsonc \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u0442 \u043E\u0448\u0438\u0431\u043A\u0443; \u0444\u0430\u0439\u043B \u043D\u0435 \u0438\u0437\u043C\u0435\u043D\u0451\u043D");
  return value;
}
async function applyConfig({ configPath, stateDir, envelope, serverURL, previous, client = "opencode" }) {
  const clean = validateConfig(envelope, serverURL);
  const fingerprint = digest(JSON.stringify(clean));
  if (previous && clean.revision < previous.revision)
    throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u043F\u0440\u0438\u0441\u043B\u0430\u043B \u0431\u043E\u043B\u0435\u0435 \u0441\u0442\u0430\u0440\u0443\u044E \u0432\u0435\u0440\u0441\u0438\u044E \u043A\u043E\u043D\u0444\u0438\u0433\u0430");
  if (previous?.revision === clean.revision && previous.fingerprint !== fingerprint)
    throw new Error("\u0421\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0435 \u043A\u043E\u043D\u0444\u0438\u0433\u0430 \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u043E\u0441\u044C \u0431\u0435\u0437 \u0443\u0432\u0435\u043B\u0438\u0447\u0435\u043D\u0438\u044F \u0432\u0435\u0440\u0441\u0438\u0438");
  let text2 = await readFile2(configPath, "utf8");
  const current = parseConfig(text2);
  const source = clean.config.providers.corporate;
  const field = client === "kilo" ? "provider" : "providers";
  const currentRef = client === "kilo" ? current[field]?.corporate?.options?.apiKey : current[field]?.corporate?.settings?.apiKey;
  const references = ["access-token", "access-token-next"].map((name) => `{file:${join2(stateDir, name)}}`);
  const apiKey = references.includes(currentRef) ? currentRef : references[0];
  const provider = client === "kilo" ? { name: source.name, npm: "@ai-sdk/openai-compatible", options: { baseURL: source.settings.baseURL, apiKey }, models: source.models } : { ...source, package: "@ai-sdk/openai-compatible", settings: { ...source.settings, apiKey } };
  const changed = JSON.stringify(current[field]?.corporate) !== JSON.stringify(provider);
  if (changed) {
    const backup = `${configPath}.before-corporate.bak`;
    if (!await exists(backup))
      await atomicWrite(backup, text2);
    text2 = applyEdits(text2, modify(text2, [field, "corporate"], provider, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
    parseConfig(text2);
    await atomicWrite(configPath, text2);
  }
  return { revision: clean.revision, fingerprint, changed, checkedAt: new Date().toISOString() };
}
async function rotateProviderTokenReference(configPath, stateDir, client = "opencode") {
  const original = await readFile2(configPath, "utf8");
  const current = parseConfig(original);
  const field = client === "kilo" ? "provider" : "providers";
  const path = [field, "corporate", client === "kilo" ? "options" : "settings", "apiKey"];
  const provider = current[field]?.corporate;
  if (!provider)
    return false;
  const oldRef = client === "kilo" ? provider.options?.apiKey : provider.settings?.apiKey;
  const first = `{file:${join2(stateDir, "access-token")}}`;
  const second = `{file:${join2(stateDir, "access-token-next")}}`;
  if (oldRef !== first && oldRef !== second)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0430\u044F \u0441\u0441\u044B\u043B\u043A\u0430 \u043D\u0430 \u0442\u043E\u043A\u0435\u043D \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430");
  const updated = applyEdits(original, modify(original, path, oldRef === first ? second : first, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  parseConfig(updated);
  await atomicWrite(configPath, updated);
  return true;
}
async function removeProvider(configPath, client = "opencode") {
  let text2 = await readFile2(configPath, "utf8");
  const original = text2;
  const current = parseConfig(text2);
  const field = client === "kilo" ? "provider" : "providers";
  if (object(current[field])) {
    const count = Object.keys(current[field]).length;
    if (Object.hasOwn(current[field], "corporate") || count === 0) {
      const path = count <= 1 ? [field] : [field, "corporate"];
      text2 = applyEdits(text2, modify(text2, path, undefined, {}));
    }
  }
  if (client === "kilo") {
    for (const key of ["model", "small_model", "subagent_model"]) {
      if (typeof current[key] === "string" && current[key].startsWith("corporate/"))
        text2 = applyEdits(text2, modify(text2, [key], undefined, {}));
    }
  }
  if (text2 === original)
    return;
  parseConfig(text2);
  await atomicWrite(configPath, text2);
}
async function syncMCP(configPath, stateDir, configs, path) {
  const original = await readFile2(configPath, "utf8");
  let text2 = original;
  const current = parseConfig(text2);
  const existing = path.length === 1 ? current.mcp : current.mcp?.servers;
  const managedConfigs = object(existing) ? existing : {};
  const managed = Object.keys(managedConfigs).filter((name) => name.startsWith("corp_"));
  const wanted = new Map(configs.map(({ name, config }) => {
    if (!name.startsWith("corp_") || config.headers?.Authorization !== `Bearer {env:${mcpEnvName(stateDir, name.slice(5))}}`)
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0430\u044F MCP \u043A\u043E\u043D\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044F");
    return [name, { type: "remote", url: config.url, oauth: false, headers: { Authorization: config.headers.Authorization } }];
  }));
  if (managed.length === wanted.size && managed.every((name) => JSON.stringify(managedConfigs[name]) === JSON.stringify(wanted.get(name))))
    return false;
  for (const name of managed)
    if (!wanted.has(name))
      text2 = applyEdits(text2, modify(text2, [...path, name], undefined, {}));
  for (const [name, config] of wanted)
    text2 = applyEdits(text2, modify(text2, [...path, name], config, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  const updated = parseConfig(text2);
  const section = path.length === 1 ? updated.mcp : updated.mcp?.servers;
  if (!Object.keys(object(section) ? section : {}).length)
    text2 = applyEdits(text2, modify(text2, path, undefined, {}));
  if (path.length > 1 && !Object.keys(parseConfig(text2).mcp ?? {}).length)
    text2 = applyEdits(text2, modify(text2, ["mcp"], undefined, {}));
  parseConfig(text2);
  const backup = `${configPath}.before-corporate.bak`;
  if (!await exists(backup))
    await atomicWrite(backup, original);
  await atomicWrite(configPath, text2);
  return true;
}
function syncKiloMCP(configPath, stateDir, configs) {
  return syncMCP(configPath, stateDir, configs, ["mcp"]);
}
function syncOpenCodeMCP(configPath, stateDir, configs) {
  return syncMCP(configPath, stateDir, configs, ["mcp", "servers"]);
}

// src/skills.js
import { mkdir as mkdir2, readFile as readFile3 } from "fs/promises";
import { join as join3 } from "path";
function validateCatalog(data) {
  if (!Array.isArray(data?.skills) || data.skills.length > 40)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043A\u0430\u0442\u0430\u043B\u043E\u0433 skills");
  const seen = new Set;
  for (const skill of data.skills) {
    if (!/^corp-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(skill.id) || skill.id.length > 80 || seen.has(skill.id))
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0438\u0434\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0442\u043E\u0440 skill");
    seen.add(skill.id);
    if (typeof skill.name !== "string" || skill.name.length > 100 || typeof skill.description !== "string" || skill.description.length > 500 || !/^[a-f0-9]{64}$/.test(skill.sha256) || typeof skill.version !== "string")
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0435 \u043C\u0435\u0442\u0430\u0434\u0430\u043D\u043D\u044B\u0435 skill");
  }
  return data.skills;
}
async function installSkills({ ids, catalog, api, token, skillsDir, signal }) {
  if (!Array.isArray(ids) || new Set(ids).size !== ids.length || ids.length > 40)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440 skills");
  const selected = ids.map((id) => {
    const skill = catalog.find((entry) => entry.id === id);
    if (!skill)
      throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D skill \u0432\u043D\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0433\u043E \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430");
    return skill;
  });
  const downloads = [];
  if ((await exists(skillsDir))?.isSymbolicLink())
    throw new Error("\u041A\u0430\u0442\u0430\u043B\u043E\u0433 skills \u043D\u0435 \u0434\u043E\u043B\u0436\u0435\u043D \u0431\u044B\u0442\u044C \u0441\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0439 \u0441\u0441\u044B\u043B\u043A\u043E\u0439");
  for (const skill of selected) {
    const { data } = await api.request(`/api/skills/${encodeURIComponent(skill.id)}`, { token, signal });
    if (typeof data?.content !== "string" || data.content.length > 1e5 || digest(data.content) !== skill.sha256)
      throw new Error(`\u041A\u043E\u043D\u0442\u0440\u043E\u043B\u044C\u043D\u0430\u044F \u0441\u0443\u043C\u043C\u0430 \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u043B\u0430: ${skill.id}`);
    if (!data.content.startsWith(`---
name: ${skill.id}
`))
      throw new Error("\u0418\u043C\u044F \u0432 SKILL.md \u043D\u0435 \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u0435\u0442 \u0441 \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u043E\u043C");
    const directory = join3(skillsDir, skill.id);
    if ((await exists(directory))?.isSymbolicLink())
      throw new Error("\u041E\u0442\u043A\u0430\u0437 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438 \u0447\u0435\u0440\u0435\u0437 \u0441\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443");
    const target = join3(directory, "SKILL.md");
    const marker = join3(directory, ".corporate-sha256");
    if (await exists(target)) {
      const ownedHash = await readFile3(marker, "utf8").catch(() => "");
      if (digest(await readFile3(target, "utf8")) !== ownedHash)
        throw new Error(`Skill ${skill.id} \u0438\u0437\u043C\u0435\u043D\u0451\u043D \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E; \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0438\u0441\u044C \u043E\u0442\u043C\u0435\u043D\u0435\u043D\u0430`);
    }
    downloads.push({ directory, target, marker, content: data.content, hash: skill.sha256 });
  }
  for (const item of downloads) {
    await mkdir2(item.directory, { recursive: true, mode: 448 });
    await atomicWrite(item.target, item.content);
    await atomicWrite(item.marker, item.hash);
  }
  return selected.map((skill) => skill.id);
}

// src/community.js
import { readFile as readFile4, mkdir as mkdir3 } from "fs/promises";
import { dirname as dirname2, join as join4 } from "path";
import { fileURLToPath } from "url";

// community/manifest.json
var manifest_default = {
  "caveman-plugin/index.js": "b476ed6d45d64e7dfdaed1361e13547a84f0a354026eecfa5793b7e4de520fa4",
  "caveman-plugin/package.json": "d9cdf72f8d9daef089e513aa1f9db39293b9abdddf668f542054a74e66b5ee88",
  "caveman-plugin/rules.md": "ef99681346ed2ff1932e1264fb5cdf1b5bb8ba54d62f7f205eebbd9973979802",
  "caveman/SKILL.md": "415d43518f2b1a9498c15a445d4657117b129ee5e81b19454ce348439cc6672b",
  "grill-me/SKILL.md": "caaf8b8de1684f96e26b28f3c29189db5c89cce4b73e1c93d86164f66ef88637",
  "grilling/SKILL.md": "befdff1e27a1dfe2a294d5871169ac1afe16d983911daa4f32627514a48c1e15",
  "megacave/SKILL.md": "139105296c0686c1ee24610caca1db293ab84162beb0d94aa7a9ad7cbc3352bf",
  "ultracave/SKILL.md": "a8da5b0b3501b853e1b98f2ae09fe8dc9c0edf481b1d3fa9529f8557011c1ef8",
  "vercel-react-best-practices/AGENTS.md": "fc93e7421177bbf869cce892bc60a6c83a4517d974bc3bf65c4e2c1e58a6ccf6",
  "vercel-react-best-practices/SKILL.md": "71ed7794962fa6e803ee83030517b5b93a9f70fbfeb431ec4535c5480a8d8355",
  "vercel-react-best-practices/rules/_sections.md": "01c59969e4e867f0708c8f8ef9c6d87fab9a07d0586244f429ff84013db8a115",
  "vercel-react-best-practices/rules/_template.md": "99df2a3ea088c6c22de2484ddc7e964d0e9923846f44c63380343ecc64455442",
  "vercel-react-best-practices/rules/advanced-effect-event-deps.md": "55ed8f9f27a1bff803d6fa55828176207714b02123cbb97ddb8a90d88024a723",
  "vercel-react-best-practices/rules/advanced-event-handler-refs.md": "a3097edeecfb2ff6851cd66ed8cdf0617c3c88180504bee824aa6e75a215bbbc",
  "vercel-react-best-practices/rules/advanced-init-once.md": "3e4dc22173eb0e2b6dcf583e3babd862b8696328f8f59aee7c4d746c5bc05f6c",
  "vercel-react-best-practices/rules/advanced-use-latest.md": "8a3f64dfe5a77d1564248faf17fe662ae75b55d497a243cb30b38eb07ccbbf9a",
  "vercel-react-best-practices/rules/async-api-routes.md": "523338540d73427dc14c0cbb19f2741ebccdf8b105a7b2c1b33d2905cf237a42",
  "vercel-react-best-practices/rules/async-cheap-condition-before-await.md": "03107c1f70a293cd58a8abc5474c5548e20ea4efdf01b6d45aae7ad0ac1cb32c",
  "vercel-react-best-practices/rules/async-defer-await.md": "f3c142d090615abdcc99d31c123be37b31f0f1ed8d9ec9f7789a3bc6883ae0fb",
  "vercel-react-best-practices/rules/async-dependencies.md": "16ef469f877e30c6b8e1e1b4bc3e527312fa3c6318cb785a4eca186ea236131a",
  "vercel-react-best-practices/rules/async-parallel.md": "6d2f841896279e976dfcdc1ac89e70771ac188baadfd43c096b5706cb838b961",
  "vercel-react-best-practices/rules/async-suspense-boundaries.md": "de05fedac2eb7ae563b887b5a424464ec3dfaf84e5b7797467ebe2a796ac8afc",
  "vercel-react-best-practices/rules/bundle-analyzable-paths.md": "62090b5c815fd71bf1133dce754f51abc16a9456d0ccd025fd627de27726e92a",
  "vercel-react-best-practices/rules/bundle-barrel-imports.md": "e648f6d54525f07a691357040ca5bff6ea3424788a91ff63812adb29622a671b",
  "vercel-react-best-practices/rules/bundle-conditional.md": "09c8259c3efb04fc0abb8e412ccbda217c222ae8118516283e571c995fe3a7d4",
  "vercel-react-best-practices/rules/bundle-defer-third-party.md": "3719fb47b191e8db4fe22686ec88448ad5af9e6838585425abbe103d0b642e37",
  "vercel-react-best-practices/rules/bundle-dynamic-imports.md": "401817a7369f315fc5a68a1095742ff7d53d0461906880dc9d64a41495ee1986",
  "vercel-react-best-practices/rules/bundle-preload.md": "d1f7cc28da7cd5ab249acd287edc5b761afcfb194e9cb62cd44c5f3543db2de2",
  "vercel-react-best-practices/rules/client-event-listeners.md": "242a873349febc1ce685e85617994784dbab92c2eaa68aed7fed5a83e7680e93",
  "vercel-react-best-practices/rules/client-localstorage-schema.md": "0fb7cdf9dc93fdf22f87e3669f953fb9d4ac9b0be42eec4a29fe9a2560610b88",
  "vercel-react-best-practices/rules/client-passive-event-listeners.md": "1f35016f9053de69e884ee9be00654e37979c2ca85f5e57764dc2626ff7acb4b",
  "vercel-react-best-practices/rules/client-swr-dedup.md": "644652c39c6cc00de8d1c77a7273612e868dc3f7edda30764164c12ec0f764a3",
  "vercel-react-best-practices/rules/js-batch-dom-css.md": "480b891b9eaf96e929dc1e964274a4828e3a78009b7d00ccd965a0d425215959",
  "vercel-react-best-practices/rules/js-cache-function-results.md": "3daaa11d24f4295cb6be8bc6f407f2ce83cc7b5bd1f0e68891ea8ab835721dc7",
  "vercel-react-best-practices/rules/js-cache-property-access.md": "73e47431e74878a927061bf0ddc7cd91a7556cb35d2573f3421e82300d9ae311",
  "vercel-react-best-practices/rules/js-cache-storage.md": "11b826b0433898c1ece2d3547010d8e77db9fb240185748c45db91493de9b6cc",
  "vercel-react-best-practices/rules/js-combine-iterations.md": "71add08aeeb43091d4ff4c0b2842cce8b4bdef8ad3e732cc034bb5a84827e746",
  "vercel-react-best-practices/rules/js-early-exit.md": "925ce5ce87f3347186ca62212f29cc6baa2b8c85a96d2720ad07c3d0abf781c0",
  "vercel-react-best-practices/rules/js-flatmap-filter.md": "9e5b166a41914d975bef7635467f8fb32cd98b5c3126c0bc6f163490812fb5f0",
  "vercel-react-best-practices/rules/js-hoist-regexp.md": "f9e9aef2f7c2307dd7310f283df85dcada45fc43e9bb941b0c3aa414dec21ec4",
  "vercel-react-best-practices/rules/js-index-maps.md": "5df1bdc2cfabb2c98abd55d26762e5c18189535c2e686184f426082e62920391",
  "vercel-react-best-practices/rules/js-length-check-first.md": "8b54a311c826b299272f29187fc58bc55772a04c4a72eeb29456ee96dc9fc624",
  "vercel-react-best-practices/rules/js-min-max-loop.md": "87dfb67e2f39df6ad8bcfb5b78c5fb364d3c07554ad188a202408d99f3763421",
  "vercel-react-best-practices/rules/js-request-idle-callback.md": "ee08f83905b4011abbc33d594033157d77561b5bbd9b36b04f0f409581ffec32",
  "vercel-react-best-practices/rules/js-set-map-lookups.md": "a7fd781a6ba9ad49065961b6f9a90ef486bf6b648390e1a08704025f98e1642b",
  "vercel-react-best-practices/rules/js-tosorted-immutable.md": "d0a5e1b0fec48a0a81397957e2f068e224329f7c42cb5feeed8aae6fa64025e8",
  "vercel-react-best-practices/rules/rendering-activity.md": "1e5e7eaf3555e61d6a2e900089c676527d26259501db5594f59544b6c664f85a",
  "vercel-react-best-practices/rules/rendering-animate-svg-wrapper.md": "9c6ae0ca7a51434e803887c64cded760956579a1452ccb80a461a03f9c937c77",
  "vercel-react-best-practices/rules/rendering-conditional-render.md": "2ec2fa23c4148285144687050c52369adba3da2fbe3d486f8d3e0aad8f06f2bc",
  "vercel-react-best-practices/rules/rendering-content-visibility.md": "64eee6d5b916fe74df33363994b27fc7f71bea3bcedc7ee04bda23107ca3e6e4",
  "vercel-react-best-practices/rules/rendering-hoist-jsx.md": "93b229560fae92005ed9a2a829064607b39b2e984e92d221d05b2d41df2b7c0e",
  "vercel-react-best-practices/rules/rendering-hydration-no-flicker.md": "dc7ab358c67c177bca6e6f360fbc935ebe4efa928c0ba3ebd3f9f3d9e2000ca3",
  "vercel-react-best-practices/rules/rendering-hydration-suppress-warning.md": "915bacb934e2927d84b37a3f3d225a47b309ac8f9e494ed2bcb66ce07c5676a2",
  "vercel-react-best-practices/rules/rendering-resource-hints.md": "351b1095d641717b930f1b2253282b7120af3023bc74e06c17675168d4286864",
  "vercel-react-best-practices/rules/rendering-script-defer-async.md": "4cea07b7875ba7fc2c7465ff23b63a2bb334f90aaf2d9293d38d67b05fdb32ab",
  "vercel-react-best-practices/rules/rendering-svg-precision.md": "ed468533f6e95f622859c884b122cf21f9f593ed6bb3d500a54de4b9f9bcb9fb",
  "vercel-react-best-practices/rules/rendering-usetransition-loading.md": "3a1249c3f13026b6f54ab5712c388df219d6af01b12aa542749acd99a46f4bc1",
  "vercel-react-best-practices/rules/rerender-defer-reads.md": "234050a77faf50cb306be10a9e15bd4421134ab5907e75f13e6d78e2bd262dc9",
  "vercel-react-best-practices/rules/rerender-dependencies.md": "17eb5830956fb56486fd3cfc7431f5849d39751730c05ad9e77dd4f0c27169c5",
  "vercel-react-best-practices/rules/rerender-derived-state-no-effect.md": "cb11ec76f50aa7b6847269f02d79b120c889a30d9ecd2c1d578f75144419c77a",
  "vercel-react-best-practices/rules/rerender-derived-state.md": "1c326bb67b01fb084eb00c8911b0a7cff54681c2315b629f88e49b64eaa6481d",
  "vercel-react-best-practices/rules/rerender-functional-setstate.md": "5e68df6b2ae8058e67f476ff1ac67bde159f5a9d18df439e46eabcdeb7b52e58",
  "vercel-react-best-practices/rules/rerender-lazy-state-init.md": "4ae844740f266fc8cbf050701230286624a2440ec5be67b9a63d9edc3c580573",
  "vercel-react-best-practices/rules/rerender-memo-with-default-value.md": "81c47476564ad8a79fc68fc442734255ca7d6829424359464503fda0a9f9a0dd",
  "vercel-react-best-practices/rules/rerender-memo.md": "1f258990c2f27ff6256b3cc5c43300631bb3f0d81f749aed08d07fcdcc131dd1",
  "vercel-react-best-practices/rules/rerender-move-effect-to-event.md": "abc2cbf167bee056743023351e96806a411d3398da8802093620aecf0721f029",
  "vercel-react-best-practices/rules/rerender-no-inline-components.md": "1cc32907a770272524ba682eef9e7efdd8ad4533b6f89b718a1fcd7d1d0eb6a3",
  "vercel-react-best-practices/rules/rerender-simple-expression-in-memo.md": "5bdcf2d1558ba5204e643c887b7b4060f89630969425651eb68e96427d97f800",
  "vercel-react-best-practices/rules/rerender-split-combined-hooks.md": "6f45d703343484ef9acef9388397f3642966ae6a5a258899a0cf1f9977cfbf6c",
  "vercel-react-best-practices/rules/rerender-transitions.md": "60f4033909a62df5e5b8c601494f9e50a562e2f8c1c2d81eac24f38142265f1c",
  "vercel-react-best-practices/rules/rerender-use-deferred-value.md": "8c3579576a61a949884167745dcfaf1d5426ba305cc61fd0a79602d70fda4909",
  "vercel-react-best-practices/rules/rerender-use-ref-transient-values.md": "f1a649af9d1d0b5c762f6c9c4c1c70c90d7df82aa10296ee87aadb78c1b76c54",
  "vercel-react-best-practices/rules/server-after-nonblocking.md": "d0b8d24a3db9f0f65f9e2bddbf230b0e03a5f60e1229d93a4a18f5e7a991c7c2",
  "vercel-react-best-practices/rules/server-auth-actions.md": "a2ca8aa102839251c7971ec784560fab943c20b36fe6f80365d4110c13260c23",
  "vercel-react-best-practices/rules/server-cache-lru.md": "1924b64561841923b88a657085097a0aeba3e0ba2d5470b9f5c15cc10d6ae70f",
  "vercel-react-best-practices/rules/server-cache-react.md": "fddeea6c870bb3da4134b61d54b7d09b83d2603f929b7547cd3dc1dc269edd5c",
  "vercel-react-best-practices/rules/server-dedup-props.md": "c2747424cdac46be62f835f245a0aa887b0090b416d28e2ac8676702645eeb37",
  "vercel-react-best-practices/rules/server-hoist-static-io.md": "5abea4dd882b13661bd5f7dfb93f9e547d5f08176c61c448ade91b210ed5d49f",
  "vercel-react-best-practices/rules/server-no-shared-module-state.md": "4d869bf1cd2f1632e5ca4c0e64b1cf0e71c5f5a0f940bc8a22174d205e735ed7",
  "vercel-react-best-practices/rules/server-parallel-fetching.md": "569a2e9fc04f9606686cd75c5894ef8781b502786a7fffe241396846c7733472",
  "vercel-react-best-practices/rules/server-parallel-nested-fetching.md": "ad5d9656984d4a959997a2367bf59cc6632297b4634a1dd13a087939d83f30b3",
  "vercel-react-best-practices/rules/server-serialization.md": "f4c7d68b29c82381baad059c4a7f09e868e71ec9c3115a26ad3ae7d24c0dfe1f"
};

// src/community.js
var SUPERPOWERS_SPEC = "superpowers@git+https://github.com/obra/superpowers.git#8ca22dba9a94f28898bbce59f2537ff4d87c747d";
var CAVEMAN_SPEC = "./community-plugins/caveman";
var packages = Object.freeze([
  { id: "community-superpowers", name: "Superpowers", kind: "plugin", client: "opencode", version: "8ca22db", description: "\u041C\u0435\u0442\u043E\u0434\u0438\u043A\u0430 \u0440\u0430\u0437\u0440\u0430\u0431\u043E\u0442\u043A\u0438 \u0438 \u043D\u0430\u0431\u043E\u0440 skills; OpenCode V2 plugin (obra/superpowers)." },
  { id: "community-caveman", name: "Caveman", kind: "plugin", client: "opencode", version: "2e08b91", description: "\u041A\u0440\u0430\u0442\u043A\u0438\u0435 \u043E\u0442\u0432\u0435\u0442\u044B \u0441 \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u0438\u0435\u043C \u0444\u0430\u043A\u0442\u043E\u0432; OpenCode V2 \u0430\u0434\u0430\u043F\u0442\u0435\u0440, /caveman on|off." },
  { id: "community-grill-me", name: "Grill me", kind: "skill", version: "b0618bc", description: "\u041F\u0440\u043E\u0432\u0435\u0440\u043A\u0430 \u0438\u0434\u0435\u0438 \u0432\u043E\u043F\u0440\u043E\u0441\u0430\u043C\u0438; \u0432\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u0437\u0430\u0432\u0438\u0441\u0438\u043C\u044B\u0439 grilling (mattpocock/skills)." },
  { id: "community-react-best-practices", name: "React Best Practices", kind: "skill", version: "063bee9", description: "70 \u043F\u0440\u0430\u0432\u0438\u043B \u043F\u0440\u043E\u0438\u0437\u0432\u043E\u0434\u0438\u0442\u0435\u043B\u044C\u043D\u043E\u0441\u0442\u0438 React/Next.js \u043E\u0442 Vercel; \u0434\u043B\u044F frontend \u0437\u0430\u0434\u0430\u0447." }
]);
function communityCatalog(client) {
  return packages.filter((item) => !item.client || item.client === client);
}
function packageFiles(id) {
  const prefixes = {
    "community-caveman": ["caveman/", "ultracave/", "megacave/", "caveman-plugin/"],
    "community-grill-me": ["grill-me/", "grilling/"],
    "community-react-best-practices": ["vercel-react-best-practices/"]
  }[id] ?? [];
  return Object.keys(manifest_default).filter((path) => prefixes.some((prefix) => path.startsWith(prefix)));
}
async function assetRoot() {
  const here = dirname2(fileURLToPath(import.meta.url));
  for (const candidate of [join4(here, "community"), join4(here, "..", "community")]) {
    if (await exists(join4(candidate, "manifest.json")))
      return candidate;
  }
  throw new Error("\u0412 \u043F\u0430\u043A\u0435\u0442\u0435 \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043A\u0430\u0442\u0430\u043B\u043E\u0433 community skills");
}
function destination(path, { skillsDir, configPath }) {
  if (path.startsWith("caveman-plugin/"))
    return join4(dirname2(configPath), "community-plugins", "caveman", path.slice("caveman-plugin/".length));
  return join4(skillsDir, path);
}
function ownerFile(folder) {
  return join4(folder, ".community-source.json");
}
async function preflightGroup(files, group, options) {
  const marker = ownerFile(group);
  const parent = await exists(group);
  if (parent?.isSymbolicLink())
    throw new Error(`\u0421\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0441\u044B\u043B\u043A\u0430 \u0437\u0430\u043F\u0440\u0435\u0449\u0435\u043D\u0430: ${group}`);
  let owned = null;
  if (await exists(marker)) {
    try {
      owned = JSON.parse(await readFile4(marker, "utf8"));
    } catch {
      throw new Error(`\u041F\u043E\u0432\u0440\u0435\u0436\u0434\u0451\u043D \u043C\u0430\u0440\u043A\u0435\u0440 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438: ${marker}`);
    }
    if (!owned || typeof owned.files !== "object")
      throw new Error(`\u041F\u043E\u0432\u0440\u0435\u0436\u0434\u0451\u043D \u043C\u0430\u0440\u043A\u0435\u0440 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438: ${marker}`);
  } else if (parent)
    throw new Error(`\u041A\u0430\u0442\u0430\u043B\u043E\u0433 ${group} \u0443\u0436\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 \u0438 \u043D\u0435 \u0443\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u0442\u0441\u044F /skills_load`);
  for (const path of files) {
    const target = destination(path, options);
    for (let parentPath = dirname2(target);parentPath !== group && parentPath.startsWith(`${group}/`); parentPath = dirname2(parentPath)) {
      if ((await exists(parentPath))?.isSymbolicLink())
        throw new Error(`\u0421\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0441\u044B\u043B\u043A\u0430 \u0437\u0430\u043F\u0440\u0435\u0449\u0435\u043D\u0430: ${parentPath}`);
    }
    const stat = await exists(target);
    if (stat?.isSymbolicLink())
      throw new Error(`\u0421\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0441\u044B\u043B\u043A\u0430 \u0437\u0430\u043F\u0440\u0435\u0449\u0435\u043D\u0430: ${target}`);
    if (stat) {
      if (!owned?.files?.[path] || digest(await readFile4(target)) !== owned.files[path])
        throw new Error(`\u0424\u0430\u0439\u043B \u0438\u0437\u043C\u0435\u043D\u0451\u043D \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E: ${target}`);
    } else if (owned?.files?.[path])
      throw new Error(`\u0424\u0430\u0439\u043B \u0443\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u043C\u043E\u0433\u043E skill \u0443\u0434\u0430\u043B\u0451\u043D: ${target}`);
  }
  return { group, marker, files };
}
function configPlugins(text2) {
  const errors = [];
  const parsed = parse2(text2, errors, { allowTrailingComma: true });
  if (errors.length || !parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 opencode.jsonc");
  if (parsed.plugins !== undefined && !Array.isArray(parsed.plugins))
    throw new Error("plugins \u0434\u043E\u043B\u0436\u0435\u043D \u0431\u044B\u0442\u044C \u043C\u0430\u0441\u0441\u0438\u0432\u043E\u043C");
  return parsed.plugins ?? [];
}
async function addPlugins(configPath, wanted) {
  if (!wanted.length)
    return [];
  const text2 = await readFile4(configPath, "utf8");
  const current = configPlugins(text2);
  for (const spec of wanted) {
    const name = spec === CAVEMAN_SPEC ? "caveman" : "superpowers";
    if (current.some((entry) => JSON.stringify(entry).toLowerCase().includes(name) && entry !== spec)) {
      throw new Error(`${name} \u0443\u0436\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D \u0434\u0440\u0443\u0433\u0438\u043C \u0441\u043F\u043E\u0441\u043E\u0431\u043E\u043C; \u043F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 plugins \u0432 ${configPath}`);
    }
  }
  const added = wanted.filter((spec) => !current.includes(spec));
  if (!added.length)
    return [];
  const next = applyEdits(text2, modify(text2, ["plugins"], [...current, ...added], { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  configPlugins(next);
  const backup = `${configPath}.before-community.bak`;
  if (!await exists(backup))
    await atomicWrite(backup, text2);
  await atomicWrite(configPath, next);
  return added;
}
async function installCommunity({ ids, client, skillsDir, configPath }) {
  const catalog = communityCatalog(client);
  if (!Array.isArray(ids) || ids.length > catalog.length || new Set(ids).size !== ids.length)
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440 community skills");
  const selected = ids.map((id) => {
    const item = catalog.find((entry) => entry.id === id);
    if (!item)
      throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u044B\u0439 \u0438\u043B\u0438 \u043D\u0435\u0441\u043E\u0432\u043C\u0435\u0441\u0442\u0438\u043C\u044B\u0439 community skill");
    return item;
  });
  if (!selected.length)
    return [];
  if ((await exists(skillsDir))?.isSymbolicLink())
    throw new Error("\u041A\u0430\u0442\u0430\u043B\u043E\u0433 skills \u043D\u0435 \u0434\u043E\u043B\u0436\u0435\u043D \u0431\u044B\u0442\u044C \u0441\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0439 \u0441\u0441\u044B\u043B\u043A\u043E\u0439");
  const root = await assetRoot();
  const all = new Map;
  const groups = new Map;
  for (const item of selected)
    for (const path of packageFiles(item.id)) {
      const content = await readFile4(join4(root, path));
      if (digest(content) !== manifest_default[path])
        throw new Error(`\u041F\u043E\u0432\u0440\u0435\u0436\u0434\u0451\u043D \u0444\u0430\u0439\u043B \u043F\u043E\u0441\u0442\u0430\u0432\u043A\u0438: ${path}`);
      const target = destination(path, { skillsDir, configPath });
      const group = path.startsWith("caveman-plugin/") ? join4(dirname2(configPath), "community-plugins", "caveman") : join4(skillsDir, path.split("/")[0]);
      all.set(path, { target, content, group });
      groups.set(group, [...groups.get(group) ?? [], path]);
    }
  const preflight = [];
  for (const [group, files] of groups)
    preflight.push(await preflightGroup(files, group, { skillsDir, configPath }));
  const wanted = client === "opencode" ? selected.filter((item) => item.kind === "plugin").map((item) => item.id === "community-caveman" ? CAVEMAN_SPEC : SUPERPOWERS_SPEC) : [];
  if (wanted.length) {
    const current = configPlugins(await readFile4(configPath, "utf8"));
    for (const spec of wanted) {
      const name = spec === CAVEMAN_SPEC ? "caveman" : "superpowers";
      if (current.some((entry) => JSON.stringify(entry).toLowerCase().includes(name) && entry !== spec))
        throw new Error(`${name} \u0443\u0436\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D \u0434\u0440\u0443\u0433\u0438\u043C \u0441\u043F\u043E\u0441\u043E\u0431\u043E\u043C`);
    }
  }
  for (const { group, marker, files } of preflight) {
    await mkdir3(group, { recursive: true, mode: 448 });
    for (const path of files) {
      const { target, content } = all.get(path);
      await atomicWrite(target, content);
    }
    await atomicWrite(marker, JSON.stringify({ files: Object.fromEntries(files.map((path) => [path, manifest_default[path]])) }, null, 2));
  }
  await addPlugins(configPath, wanted);
  return selected.map((item) => `${item.name} (${item.kind === "plugin" ? "plugin" : "skill"})`);
}

// src/secret-page.js
import { createServer } from "http";
var maxToken = 512;
function page(items, action, csrf) {
  const fields = items.map((item, index) => `<section class="system"><div class="system-head"><span class="number">${String(index + 1).padStart(2, "0")}</span><div><h2>${escapeHTML(item.name)}</h2><p>${escapeHTML(item.description)}</p></div></div><label for="token-${index}">\u041B\u0438\u0447\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D</label><input id="token-${index}" name="token:${escapeHTML(item.id)}" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="${maxToken}" placeholder="\u0412\u0441\u0442\u0430\u0432\u044C\u0442\u0435 \u0442\u043E\u043A\u0435\u043D \u0434\u043B\u044F ${escapeHTML(item.name)}" required></section>`).join("");
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435 MCP</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 90% 0%,#d7ebe8 0,transparent 38%),#f3f6f7}main{width:min(720px,calc(100% - 32px));margin:56px auto 72px}.brand{display:flex;align-items:center;gap:12px;color:#264e54;font-size:13px;font-weight:750;letter-spacing:.11em;text-transform:uppercase}.mark{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#15766d;color:white;font-size:21px;font-weight:700;letter-spacing:0}.panel{margin-top:22px;padding:clamp(24px,5vw,44px);background:#fff;border:1px solid #e0e8e9;border-radius:24px;box-shadow:0 20px 60px #1c434b12}h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.15;letter-spacing:-.035em}.lead{margin:15px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}.notice{display:flex;gap:12px;margin:26px 0 8px;padding:15px 17px;background:#ecf8f5;border:1px solid #cce8e1;border-radius:13px;color:#275f57;font-size:14px;line-height:1.45}.notice b{font-size:18px;line-height:1}.system{padding:25px 0;border-bottom:1px solid #e9eef0}.system-head{display:flex;gap:16px;align-items:flex-start}.number{display:grid;place-items:center;flex:none;width:35px;height:35px;border-radius:10px;background:#eaf1f2;color:#4b7278;font-size:12px;font-weight:750}.system h2{margin:1px 0 5px;font-size:19px;letter-spacing:-.015em}.system p{margin:0;color:#64747e;font-size:14px;line-height:1.45}.system label{display:block;margin:20px 0 8px;color:#344a54;font-size:13px;font-weight:700}.system input{display:block;width:100%;height:48px;padding:0 14px;border:1px solid #bdcdd1;border-radius:10px;background:#fbfdfd;color:#17212b;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}.system input:focus{border-color:#15766d;box-shadow:0 0 0 4px #15766d20}.system input::placeholder{color:#9ba9ae}.footer{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:28px}.footnote{max-width:350px;color:#667780;font-size:13px;line-height:1.45}button{border:0;border-radius:11px;padding:14px 23px;background:#126d64;color:#fff;font:inherit;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 6px 16px #126d642d}button:hover{background:#0d5a52}button:focus-visible{outline:3px solid #71cabe;outline-offset:3px}@media(max-width:600px){main{margin:24px auto 40px}.panel{border-radius:18px}.footer{align-items:stretch;flex-direction:column-reverse}button{width:100%}}
  </style></head><body><main><div class="brand"><span class="mark">\u2197</span> \u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u044B</div><div class="panel"><h1>\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0435 \u0441\u0438\u0441\u0442\u0435\u043C\u044B</h1><p class="lead">\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0434\u043B\u044F ${items.length} ${items.length % 10 === 1 && items.length % 100 !== 11 ? "\u0441\u0438\u0441\u0442\u0435\u043C\u044B" : "\u0441\u0438\u0441\u0442\u0435\u043C"}. \u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442 MCP \u0432 \u0442\u0435\u043A\u0443\u0449\u0435\u043C \u0437\u0430\u043F\u0443\u0441\u043A\u0435 OpenCode \u0438\u043B\u0438 Kilo.</p><div class="notice"><b>\u25C8</b><span>\u0422\u043E\u043A\u0435\u043D\u044B \u043F\u0435\u0440\u0435\u0434\u0430\u044E\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u043C\u0443 \u043F\u043B\u0430\u0433\u0438\u043D\u0443. \u041E\u043D\u0438 \u043D\u0435 \u043F\u043E\u044F\u0432\u044F\u0442\u0441\u044F \u0432 \u0447\u0430\u0442\u0435 \u0438 \u043D\u0435 \u0431\u0443\u0434\u0443\u0442 \u0437\u0430\u043F\u0438\u0441\u0430\u043D\u044B \u0432 \u0444\u0430\u0439\u043B \u043A\u043E\u043D\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438.</span></div><form method="post" action="${action}" autocomplete="off"><input type="hidden" name="csrf" value="${csrf}">${fields}<div class="footer"><span class="footnote">\u041F\u043E\u0441\u043B\u0435 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u043A\u0430 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u044F \u043F\u043E\u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0432\u0432\u0435\u0441\u0442\u0438 \u0442\u043E\u043A\u0435\u043D\u044B \u0441\u043D\u043E\u0432\u0430.</span><button type="submit">\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C ${items.length} MCP</button></div></form></div></main></body></html>`;
}
function resultPage(outcome = {}) {
  const kind = ["success", "warning", "error"].includes(outcome.kind) ? outcome.kind : "warning";
  const title = escapeHTML(outcome.title ?? "\u0422\u043E\u043A\u0435\u043D\u044B \u043F\u0435\u0440\u0435\u0434\u0430\u043D\u044B");
  const message = escapeHTML(outcome.message ?? "\u041F\u043B\u0430\u0433\u0438\u043D \u043E\u0431\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u0435\u0442 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435.");
  const icon = { success: "\u2713", warning: "\xB7", error: "!" }[kind];
  const items = Array.isArray(outcome.items) ? outcome.items.map((item) => {
    const state = item.status === "connected" ? "ok" : item.status === "failed" ? "bad" : "wait";
    return `<li><span class="dot ${state}">${{ ok: "\u2713", bad: "!", wait: "\xB7" }[state]}</span><span><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.detail ?? "")}</small></span></li>`;
  }).join("") : "";
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>${title}</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0%,#d7ebe8 0,transparent 40%),#f3f6f7}main{width:min(620px,calc(100% - 32px));margin:9vh auto 48px}.brand{color:#37666a;font-size:12px;font-weight:750;letter-spacing:.12em;text-transform:uppercase}.card{margin-top:20px;padding:clamp(26px,5vw,42px);border:1px solid #e0e8e9;border-radius:24px;background:#fff;box-shadow:0 20px 60px #1c434b12}.icon{display:grid;place-items:center;width:54px;height:54px;border-radius:17px;font-size:29px;font-weight:700;background:#e7f5ef;color:#16805c}.warning .icon{background:#fff4da;color:#a56b14}.error .icon{background:#fcebea;color:#bd5149}h1{margin:24px 0 0;font-size:clamp(28px,4vw,36px);line-height:1.15;letter-spacing:-.035em}p{margin:13px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}ul{list-style:none;margin:27px 0 0;padding:0;border-top:1px solid #edf0f1}li{display:flex;gap:13px;align-items:flex-start;padding:16px 0;border-bottom:1px solid #edf0f1}.dot{display:grid;place-items:center;flex:none;width:27px;height:27px;border-radius:9px;font-size:15px;font-weight:750}.dot.ok{background:#e7f5ef;color:#16805c}.dot.bad{background:#fcebea;color:#bd5149}.dot.wait{background:#edf1f3;color:#667780}strong{display:block;font-size:15px}small{display:block;margin-top:4px;color:#6a7981;font-size:13px;line-height:1.4}.footer{margin-top:25px;color:#7c8b92;font-size:13px}@media(max-width:600px){main{margin:24px auto}.card{border-radius:18px}}
  </style></head><body><main class="${kind}"><div class="brand">\u2197 \u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u044B</div><div class="card"><div class="icon">${icon}</div><h1>${title}</h1><p>${message}</p>${items ? `<ul>${items}</ul>` : ""}<div class="footer">\u042D\u0442\u0443 \u0432\u043A\u043B\u0430\u0434\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u0437\u0430\u043A\u0440\u044B\u0442\u044C.</div></div></main></body></html>`;
}
async function captureSecrets(items, { timeoutMs = 300000, onSubmit } = {}) {
  if (!Array.isArray(items) || !items.length || items.length > 30 || new Set(items.map((item) => item.id)).size !== items.length || items.some((item) => !/^[a-z][a-z0-9_-]{0,39}$/.test(item.id)))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0441\u043F\u0438\u0441\u043E\u043A MCP \u0434\u043B\u044F \u0432\u0432\u043E\u0434\u0430 \u0442\u043E\u043A\u0435\u043D\u043E\u0432");
  const nonce = random();
  const csrf = random();
  let settled = false;
  let processing = false;
  let accept, reject;
  const result = new Promise((yes, no) => {
    accept = yes;
    reject = no;
  });
  const server = createServer(async (request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const path = `/secret/${nonce}`;
    const headers = { "Cache-Control": "no-store", Pragma: "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
    if (request.url !== path || request.headers.host !== `127.0.0.1:${server.address().port}`) {
      response.writeHead(404, headers).end();
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(page(items, path, csrf));
      return;
    }
    if (request.method !== "POST" || request.headers.origin && request.headers.origin !== origin && request.headers.origin !== "null" || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") {
      response.writeHead(403, headers).end();
      return;
    }
    let input = "";
    try {
      for await (const chunk of request) {
        input += chunk;
        if (input.length > 65536) {
          response.writeHead(413, headers).end();
          return;
        }
      }
    } catch {
      if (!response.writableEnded)
        response.writeHead(400, headers).end();
      return;
    }
    const form = new URLSearchParams(input);
    if (form.getAll("csrf").length !== 1 || form.get("csrf") !== csrf) {
      response.writeHead(403, headers).end();
      return;
    }
    const expected = new Set(items.map((item) => `token:${item.id}`));
    if ([...form.keys()].some((key) => key !== "csrf" && !expected.has(key)) || [...expected].some((key) => form.getAll(key).length !== 1 || !form.get(key) || form.get(key).length > maxToken || /[\r\n]/.test(form.get(key)))) {
      response.writeHead(400, { ...headers, "Content-Type": "text/plain; charset=utf-8" }).end("\u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0438 \u043F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0443.");
      return;
    }
    if (settled || processing) {
      response.writeHead(409, headers).end();
      return;
    }
    processing = true;
    const tokens = new Map(items.map((item) => [item.id, form.get(`token:${item.id}`)]));
    try {
      const outcome = await onSubmit?.(tokens);
      if (!settled) {
        response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(resultPage(outcome));
        settled = true;
        accept(tokens);
      }
    } catch (error) {
      if (!settled) {
        response.writeHead(500, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(resultPage({ kind: "error", title: "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u0442\u044C \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435", message: "\u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 OpenCode \u0438\u043B\u0438 Kilo \u0438 \u043F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 /mcps_load." }));
        settled = true;
        reject(error);
      }
    } finally {
      server.close();
    }
  });
  await new Promise((resolve, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", resolve);
  });
  const timer = setTimeout(() => {
    if (!settled) {
      settled = true;
      reject(new Error("\u0412\u0440\u0435\u043C\u044F \u0432\u0432\u043E\u0434\u0430 \u0442\u043E\u043A\u0435\u043D\u043E\u0432 \u0438\u0441\u0442\u0435\u043A\u043B\u043E"));
      server.close();
    }
  }, timeoutMs);
  timer.unref();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return { url: `http://127.0.0.1:${server.address().port}/secret/${nonce}`, result, cancel: () => {
    if (!settled) {
      settled = true;
      reject(new Error("\u0412\u0432\u043E\u0434 \u0442\u043E\u043A\u0435\u043D\u043E\u0432 \u043E\u0442\u043C\u0435\u043D\u0451\u043D"));
      server.close();
    }
  } };
}

// src/login.js
import { createHash as createHash3, timingSafeEqual } from "crypto";
async function startLogin(api, { timeoutMs = 300000 } = {}) {
  const state = random();
  const verifier = random();
  const challenge = createHash3("sha256").update(verifier).digest("base64url");
  let resolve, reject, consumed = false, timer;
  const controller = new AbortController;
  const result = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  result.catch(() => {});
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const received = url.searchParams.get("state") ?? "";
      if (request.method !== "GET" || url.pathname !== "/callback" || consumed || !/^[A-Za-z0-9_-]{43}$/.test(received) || !timingSafeEqual(Buffer.from(received), Buffer.from(state)))
        return new Response("Invalid callback", { status: 400 });
      consumed = true;
      try {
        const token = await api.request("/oauth/token", { method: "POST", body: { code: url.searchParams.get("code"), verifier, redirectURI }, signal: controller.signal });
        resolve(token.data);
        return new Response("\u0412\u0445\u043E\u0434 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043D. \u0412\u0435\u0440\u043D\u0438\u0442\u0435\u0441\u044C \u0432 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0435.", { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
      } catch (error) {
        reject(error);
        return new Response("\u0412\u0445\u043E\u0434 \u043D\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0451\u043D. \u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 \u0432\u0445\u043E\u0434 \u0432 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0438.", { status: 400 });
      } finally {
        clearTimeout(timer);
        setTimeout(() => server.stop(true), 100).unref();
      }
    }
  });
  const redirectURI = `http://127.0.0.1:${server.port}/callback`;
  const cancel = () => {
    clearTimeout(timer);
    controller.abort();
    server.stop(true);
    reject(new Error("\u0412\u0445\u043E\u0434 \u043E\u0442\u043C\u0435\u043D\u0451\u043D \u0438\u043B\u0438 \u0432\u0440\u0435\u043C\u044F \u043E\u0436\u0438\u0434\u0430\u043D\u0438\u044F \u0438\u0441\u0442\u0435\u043A\u043B\u043E"));
  };
  try {
    const { data } = await api.request("/oauth/requests", { method: "POST", body: { state, challenge, redirectURI }, signal: controller.signal });
    if (new URL(data.authorizationURL).origin !== new URL(api.baseURL).origin)
      throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u0432\u0435\u0440\u043D\u0443\u043B \u043D\u0435\u043E\u0436\u0438\u0434\u0430\u043D\u043D\u044B\u0439 \u0430\u0434\u0440\u0435\u0441 \u0432\u0445\u043E\u0434\u0430");
    timer = setTimeout(cancel, timeoutMs);
    timer.unref();
    return { url: data.authorizationURL, result, cancel };
  } catch (error) {
    cancel();
    throw error;
  }
}

// src/desktop.js
import { execFile } from "child_process";
import { promisify } from "util";
var exec = promisify(execFile);
async function openBrowser(url) {
  if (process.env.CORP_NO_BROWSER === "1")
    return;
  if (process.platform === "darwin")
    await exec("open", [url], { timeout: 5000 });
  else if (process.platform === "win32")
    await exec("rundll32.exe", ["url.dll,FileProtocolHandler", url], { timeout: 5000 });
  else
    await exec("xdg-open", [url], { timeout: 5000 });
}
async function notifyDesktop(message) {
  if (process.env.CORP_NO_NOTIFICATIONS === "1")
    return;
  if (process.platform === "darwin") {
    await exec("osascript", ["-e", `on run argv
 display notification (item 1 of argv) with title "Company OpenCode"
end run`, message], { timeout: 5000 });
  } else if (process.platform === "linux")
    await exec("notify-send", ["Company OpenCode", message], { timeout: 5000 });
}

// src/bridge.js
class OpenCodeBridge {
  constructor(connectionFile) {
    this.connectionFile = connectionFile;
  }
  async request(path, { method = "GET", body, signal } = {}) {
    const connection = await readJSON(this.connectionFile);
    if (!connection)
      throw new Error("\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u0434\u0435\u043C\u043E\u043F\u0440\u043E\u0444\u0438\u043B\u044C \u0447\u0435\u0440\u0435\u0437 bun run demo: \u043D\u0435\u0442 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u044F \u0441 OpenCode");
    const url = new URL(connection.url);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password)
      throw new Error("\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0439 \u0430\u0434\u0440\u0435\u0441 OpenCode");
    const result = await fetch(`${url.origin}${path}`, {
      method,
      redirect: "error",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(5000)]) : AbortSignal.timeout(5000),
      headers: { Authorization: `Basic ${Buffer.from(`opencode:${connection.password}`).toString("base64")}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined
    });
    if (!result.ok)
      throw new Error(`OpenCode API: HTTP ${result.status}`);
    return result.status === 204 ? null : result.json();
  }
  async form(sessionID, title, fields) {
    const { data } = await this.request(`/api/session/${encodeURIComponent(sessionID)}/form`, { method: "POST", body: { title, metadata: { kind: "question" }, fields } });
    return data;
  }
  message(sessionID, title, description) {
    return this.form(sessionID, title, [{ type: "string", key: "ack", title, description, custom: false, options: [{ value: "ok", label: "\u041F\u043E\u043D\u044F\u0442\u043D\u043E" }] }]);
  }
  async wait(sessionID, formID, signal) {
    const path = `/api/session/${encodeURIComponent(sessionID)}/form/${encodeURIComponent(formID)}`;
    while (!signal?.aborted) {
      const { data } = await this.request(path, { signal });
      if (data.state.status === "answered")
        return data.state.answer;
      if (data.state.status === "cancelled")
        return null;
      await sleep(400, signal);
    }
    return null;
  }
  async cancel(sessionID, formID) {
    await this.request(`/api/session/${encodeURIComponent(sessionID)}/form/${encodeURIComponent(formID)}`, { method: "DELETE" }).catch(() => {});
  }
}

// src/runtime.js
var lights = { green: "\uD83D\uDFE2", yellow: "\uD83D\uDFE1", red: "\uD83D\uDD34", unknown: "\u26AA" };
var validToken2 = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value);
var validCredential = (value) => value && validToken2(value.accessToken) && validToken2(value.inferenceToken) && validToken2(value.refreshToken) && Number.isFinite(value.expiresAt) && Number.isFinite(value.inferenceExpiresAt) && Number.isFinite(value.refreshExpiresAt) && typeof value.user?.name === "string";

class CorporateRuntime {
  constructor(options, adapters = {}) {
    this.options = options;
    this.api = adapters.api ?? new CorporateAPI(options.serverURL);
    this.bridge = adapters.bridge ?? new OpenCodeBridge(options.connectionFile);
    this.applyConfig = adapters.applyConfig ?? applyConfig;
    this.removeProvider = adapters.removeProvider ?? removeProvider;
    this.syncMCP = adapters.syncMCP;
    this.reloadProvider = adapters.reloadProvider ?? (() => rotateProviderTokenReference(this.options.configPath, this.options.stateDir, this.options.client));
    this.open = adapters.open ?? openBrowser;
    this.desktop = adapters.notify ?? notifyDesktop;
    this.queue = serial();
    this.configWrites = serial();
    this.listeners = new Set;
    this.jobs = new Set;
    this.forms = new Map;
    this.abort = new AbortController;
    this.state = {};
    this.authGeneration = 0;
    this.load = { level: "unknown", message: "\u041D\u0435\u0442 \u0441\u0432\u0435\u0436\u0438\u0445 \u0434\u0430\u043D\u043D\u044B\u0445", checkedAt: null };
    this.mcpCatalog = [];
    this.mcpConfigs = [];
    this.mcpReloaders = new Set;
  }
  async start() {
    await Promise.all([
      rm2(join5(this.options.stateDir, "mcp-selection.json"), { force: true }),
      rm2(join5(this.options.stateDir, "mcp-tokens"), { force: true, recursive: true })
    ]);
    this.credential = null;
    await rm2(join5(this.options.stateDir, "credential.json"), { force: true });
    await rm2(join5(this.options.stateDir, "sync.json"), { force: true });
    const tokenPath = join5(this.options.stateDir, "access-token");
    if (await exists(tokenPath))
      await atomicWrite(tokenPath, "");
    const alternatePath = join5(this.options.stateDir, "access-token-next");
    if (await exists(alternatePath))
      await atomicWrite(alternatePath, "");
    await this.removeProvider(this.options.configPath, this.options.client);
    await clearMCP(this.options.stateDir);
    await this.syncMCP?.([]);
    this.state = {};
    this.configTimer = setInterval(() => this.backgroundRefresh(), this.options.refreshMs);
    this.loadTimer = setInterval(() => this.pollLoad().catch(() => {}), this.options.loadPollMs);
    this.configTimer.unref();
    this.loadTimer.unref();
  }
  authenticated() {
    return Boolean(this.credential && (this.credential.refreshExpiresAt ?? this.credential.expiresAt) > Date.now());
  }
  token() {
    if (!this.authenticated() || this.credential.expiresAt <= Date.now())
      throw new Unauthorized;
    return this.credential.accessToken;
  }
  async apiToken() {
    await this.ensureFreshTokens();
    return this.token();
  }
  scheduleTokenRenewal(retryMs) {
    clearTimeout(this.tokenTimer);
    if (!this.authenticated() || !this.credential.refreshToken)
      return;
    const remaining = Math.min(this.credential.expiresAt, this.credential.inferenceExpiresAt) - Date.now();
    const delay = retryMs ?? Math.max(100, Math.floor(remaining * 0.8));
    this.tokenRenewAt = Date.now() + delay;
    this.tokenTimer = setTimeout(async () => {
      try {
        await this.ensureFreshTokens(true);
      } catch (error) {
        if (error instanceof Unauthorized)
          await this.invalidate();
        else {
          await this.notice("\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0431\u043D\u043E\u0432\u0438\u0442\u044C \u0434\u043E\u0441\u0442\u0443\u043F \u043A \u043C\u043E\u0434\u0435\u043B\u0438; \u043F\u043E\u0432\u0442\u043E\u0440\u044F\u0435\u043C \u043F\u043E\u043F\u044B\u0442\u043A\u0443", "warning");
          this.scheduleTokenRenewal(5000);
        }
      }
    }, delay);
    this.tokenTimer.unref();
  }
  async ensureFreshTokens(force = false) {
    if (!this.authenticated())
      throw new Unauthorized;
    if (!this.credential.refreshToken || !force && this.tokenRenewAt > Date.now() && this.credential.expiresAt > Date.now())
      return;
    if (this.renewing)
      return this.renewing;
    const generation = this.authGeneration;
    const old = this.credential;
    this.renewing = (async () => {
      const { data } = await this.api.request("/oauth/refresh", { method: "POST", body: { refreshToken: old.refreshToken }, signal: this.abort.signal });
      if (!validCredential(data) || data.refreshExpiresAt <= Date.now())
        throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u0432\u0435\u0440\u043D\u0443\u043B \u043D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B");
      if (generation !== this.authGeneration || this.credential !== old || this.abort.signal.aborted)
        return;
      await atomicWrite(join5(this.options.stateDir, "access-token"), data.inferenceToken);
      await atomicWrite(join5(this.options.stateDir, "access-token-next"), data.inferenceToken);
      if (generation !== this.authGeneration || this.credential !== old || this.abort.signal.aborted) {
        await Promise.all([atomicWrite(join5(this.options.stateDir, "access-token"), ""), atomicWrite(join5(this.options.stateDir, "access-token-next"), "")]);
        return;
      }
      this.credential = data;
      this.scheduleTokenRenewal();
      await this.configWrites(() => this.reloadProvider());
    })().finally(() => {
      this.renewing = null;
    });
    return this.renewing;
  }
  status() {
    return {
      authenticated: this.authenticated(),
      user: this.authenticated() ? this.credential.user : null,
      expiresAt: this.authenticated() ? this.credential.refreshExpiresAt ?? this.credential.expiresAt : null,
      config: { revision: this.state.revision ?? null, checkedAt: this.state.checkedAt ?? null, lastError: this.state.lastError ?? null },
      load: { ...this.load },
      refreshMinutes: this.options.refreshMs / 60000
    };
  }
  async notice(message, level = "info") {
    if (this.abort.signal.aborted)
      return;
    const event = { message, level, at: Date.now() };
    await Promise.allSettled([this.desktop(message), ...[...this.listeners].map((listener) => Promise.resolve().then(() => listener(event)))]);
  }
  async persistState() {
    await atomicWrite(join5(this.options.stateDir, "sync.json"), JSON.stringify(this.state, null, 2));
  }
  async refresh() {
    if (this.refreshing)
      return this.refreshing;
    this.refreshing = this.queue(async () => {
      const token = await this.apiToken();
      try {
        const response = await this.api.request("/api/config", { token, etag: this.state.etag, signal: this.abort.signal });
        if (response.unchanged)
          this.state = { ...this.state, checkedAt: new Date().toISOString(), lastError: null };
        else {
          const applied = await this.configWrites(() => this.applyConfig({ ...this.options, envelope: response.data, previous: this.state.revision ? this.state : null }));
          this.state = { ...applied, etag: response.etag, lastError: null };
          if (applied.changed)
            await this.notice(`\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433 \u043E\u0431\u043D\u043E\u0432\u043B\u0451\u043D: \u0432\u0435\u0440\u0441\u0438\u044F ${applied.revision}`, "success");
        }
        await this.persistState();
        await this.refreshMCPCatalog().catch(() => {});
        return this.state;
      } catch (error) {
        if (error instanceof Unauthorized)
          await this.invalidate();
        this.state.lastError = error instanceof Unauthorized ? error.message : "\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0431\u043D\u043E\u0432\u0438\u0442\u044C \u043A\u043E\u043D\u0444\u0438\u0433; \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u0430 \u043F\u0440\u0435\u0434\u044B\u0434\u0443\u0449\u0430\u044F \u0432\u0435\u0440\u0441\u0438\u044F";
        await this.persistState();
        throw error;
      }
    }).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }
  async backgroundRefresh() {
    if (!this.credential)
      return;
    try {
      await this.refresh();
      this.syncFailed = false;
    } catch {
      if (!this.syncFailed) {
        this.syncFailed = true;
        await this.notice(this.state.lastError ?? "\u041D\u0443\u0436\u0435\u043D \u043F\u043E\u0432\u0442\u043E\u0440\u043D\u044B\u0439 /login", "warning");
      }
    }
  }
  async invalidate() {
    this.authGeneration++;
    clearTimeout(this.tokenTimer);
    this.credential = null;
    await Promise.all([rm2(join5(this.options.stateDir, "credential.json"), { force: true }), atomicWrite(join5(this.options.stateDir, "access-token"), ""), atomicWrite(join5(this.options.stateDir, "access-token-next"), "")]);
    await clearMCP(this.options.stateDir);
    this.mcpConfigs = [];
    await this.reloadMCP();
  }
  async reloadMCP() {
    await this.syncMCP?.(this.mcpConfigs);
    await Promise.all([...this.mcpReloaders].map((reload) => reload()));
  }
  async mcpConnectionStates(ids) {
    if (!ids.length || this.options.client !== "opencode" || typeof this.bridge.request !== "function")
      return null;
    let states = [];
    for (let attempt = 0;attempt < 12; attempt++) {
      const { data } = await this.bridge.request("/api/mcp");
      states = ids.map((id) => {
        const state = data.find((entry) => entry.name === `corp_${id}`)?.status;
        return { id, status: state?.status ?? "pending", rejected: state?.status === "failed" && /HTTP 401\b/.test(state.error ?? "") };
      });
      if (states.every((entry) => entry.status === "connected"))
        break;
      if (attempt < 11)
        await sleep(250, this.abort.signal);
    }
    return states;
  }
  async refreshMCPCatalog() {
    const { data } = await this.api.request("/api/mcps", { token: await this.apiToken(), signal: this.abort.signal });
    const catalog = validateMCPCatalog(data, this.options.serverURL);
    const configs = await readMCPState(this.options.stateDir, catalog);
    this.mcpCatalog = catalog;
    this.mcpConfigs = configs;
    await this.reloadMCP();
    return catalog;
  }
  async pollLoad() {
    if (this.polling || !this.credential)
      return;
    this.polling = true;
    const polledGeneration = this.authGeneration;
    let next;
    try {
      const { data } = await this.api.request("/api/load", { token: await this.apiToken(), signal: this.abort.signal });
      if (!["green", "yellow", "red"].includes(data?.level) || typeof data.message !== "string" || data.message.length > 250 || !Number.isFinite(data.observedAt) || Math.abs(Date.now() - data.observedAt) > 90000)
        throw new Error("\u041D\u0435\u0442 \u0441\u0432\u0435\u0436\u0438\u0445 \u0434\u0430\u043D\u043D\u044B\u0445 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438");
      next = { level: data.level, message: data.message, queue: data.queue, checkedAt: data.observedAt };
    } catch (error) {
      next = { level: "unknown", message: error instanceof Unauthorized ? "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F /login" : "\u0421\u0435\u0440\u0432\u0435\u0440 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u0435\u043D", checkedAt: Date.now() };
      if (error instanceof Unauthorized)
        await this.queue(() => this.authGeneration === polledGeneration ? this.invalidate() : undefined);
    } finally {
      this.polling = false;
    }
    if (this.abort.signal.aborted)
      return;
    if (this.authGeneration !== polledGeneration)
      return;
    if (!this.credential && next.level !== "unknown")
      return;
    const changed = next.level !== this.load.level;
    this.load = next;
    if (changed)
      await this.notice(`${lights[next.level]} \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441: ${next.message}`, { green: "success", yellow: "warning", red: "error", unknown: "warning" }[next.level]);
  }
  track(promise, sessionID, interactiveError = true) {
    this.jobs.add(promise);
    promise.catch(async (error) => {
      if (!this.abort.signal.aborted) {
        if (interactiveError)
          await this.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043F\u043B\u0430\u0433\u0438\u043D", error.message).catch(() => {});
        await this.notice(error.message, "error");
      }
    }).finally(() => this.jobs.delete(promise));
  }
  async autoLogin() {
    if (this.authenticated() || this.abort.signal.aborted || process.env.CORP_NO_BROWSER === "1")
      return false;
    try {
      await this.login(null);
      return true;
    } catch (error) {
      await this.notice(`\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0442\u043A\u0440\u044B\u0442\u044C \u0432\u0445\u043E\u0434 \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438: ${error.message}. \u0412\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 /login.`, "warning");
      return false;
    }
  }
  async login(sessionID, reload = async () => {}) {
    if (this.loginFlow) {
      if (sessionID) {
        await this.open(this.loginFlow.url);
        await this.bridge.message(sessionID, "\u0412\u0445\u043E\u0434 \u043E\u0442\u043A\u0440\u044B\u0442", "\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 \u0432\u0445\u043E\u0434\u0430 \u043F\u043E\u0432\u0442\u043E\u0440\u043D\u043E \u043E\u0442\u043A\u0440\u044B\u0442\u0430 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435. \u0417\u0430\u0432\u0435\u0440\u0448\u0438\u0442\u0435 \u0430\u0432\u0442\u043E\u0440\u0438\u0437\u0430\u0446\u0438\u044E \u0442\u0430\u043C.");
      }
      return;
    }
    if (this.loginPending) {
      await this.loginPending.catch(() => {});
      return this.login(sessionID, reload);
    }
    this.loginPending = startLogin(this.api);
    const generation = this.authGeneration;
    let flow;
    try {
      flow = await this.loginPending;
    } finally {
      this.loginPending = null;
    }
    if (generation !== this.authGeneration || this.abort.signal.aborted) {
      flow.cancel();
      return;
    }
    this.loginFlow = flow;
    const clientName = this.options.client === "kilo" ? "Kilo" : "OpenCode";
    let form = sessionID ? await this.bridge.form(sessionID, `\u0412\u0445\u043E\u0434 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 ${clientName}`, [
      { type: "external", key: "login", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0443 \u0432\u0445\u043E\u0434\u0430", url: flow.url },
      { type: "string", key: "waiting", title: `\u0412\u0445\u043E\u0434 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 ${clientName}`, description: `\u0412 \u043E\u0442\u043A\u0440\u044B\u0432\u0448\u0435\u043C\u0441\u044F \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0442\u0435\u0441\u0442\u043E\u0432\u0443\u044E \u0443\u0447\u0451\u0442\u043D\u0443\u044E \u0437\u0430\u043F\u0438\u0441\u044C. \u041F\u0430\u0440\u043E\u043B\u044C \u043D\u0435 \u043D\u0443\u0436\u0435\u043D. \u0415\u0441\u043B\u0438 \u0431\u0440\u0430\u0443\u0437\u0435\u0440 \u043D\u0435 \u043E\u0442\u043A\u0440\u044B\u043B\u0441\u044F, \u0441\u043A\u043E\u043F\u0438\u0440\u0443\u0439\u0442\u0435 \u0430\u0434\u0440\u0435\u0441: ${flow.url}`, custom: false, options: [{ value: "waiting", label: "\u041E\u0436\u0438\u0434\u0430\u044E \u0432\u0445\u043E\u0434\u0430 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435" }] }
    ]).catch((error) => {
      flow.cancel();
      this.loginFlow = null;
      throw error;
    }) : null;
    try {
      await this.open(flow.url);
    } catch {
      if (form)
        await this.notice(`\u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 \u0441\u0441\u044B\u043B\u043A\u0443 \u0432\u0445\u043E\u0434\u0430 \u0432 \u0444\u043E\u0440\u043C\u0435 ${clientName}`, "info");
      else {
        flow.cancel();
        this.loginFlow = null;
        throw new Error("\u0431\u0440\u0430\u0443\u0437\u0435\u0440 \u043D\u0435 \u043E\u0442\u043A\u0440\u044B\u043B\u0441\u044F");
      }
    }
    const cancellation = new AbortController;
    if (form)
      this.bridge.wait(sessionID, form.id, AbortSignal.any([this.abort.signal, cancellation.signal])).then((answer) => {
        if (answer === null)
          flow.cancel();
      }).catch(() => {});
    this.track((async () => {
      try {
        const result = await flow.result;
        if (!validCredential(result) || result.refreshExpiresAt <= Date.now())
          throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u0432\u0435\u0440\u043D\u0443\u043B \u043D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0443\u044E \u0430\u0432\u0442\u043E\u0440\u0438\u0437\u0430\u0446\u0438\u044E");
        validateConfig(result.configuration, this.options.serverURL);
        await this.queue(async () => {
          if (generation !== this.authGeneration || this.abort.signal.aborted)
            throw new Error("\u0412\u0445\u043E\u0434 \u043E\u0442\u043C\u0435\u043D\u0451\u043D");
          this.authGeneration++;
          this.credential = { accessToken: result.accessToken, expiresAt: result.expiresAt, inferenceToken: result.inferenceToken, inferenceExpiresAt: result.inferenceExpiresAt, refreshToken: result.refreshToken, refreshExpiresAt: result.refreshExpiresAt, user: result.user };
          await clearMCP(this.options.stateDir);
          this.mcpConfigs = [];
          await this.reloadMCP();
          await atomicWrite(join5(this.options.stateDir, "access-token"), this.credential.inferenceToken);
          await atomicWrite(join5(this.options.stateDir, "access-token-next"), this.credential.inferenceToken);
          this.scheduleTokenRenewal();
          this.state = { ...await this.configWrites(() => this.applyConfig({ ...this.options, envelope: result.configuration })), lastError: null };
          await this.persistState();
        });
        await reload();
        if (form) {
          await this.bridge.cancel(sessionID, form.id);
          form = null;
        }
        await this.notice(`\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D: ${result.user.name}. \u041A\u043E\u043D\u0444\u0438\u0433 \u0432\u0435\u0440\u0441\u0438\u0438 ${this.state.revision} \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D. \u0414\u043E\u0441\u0442\u0443\u043F\u043D\u044B /refresh_config \u0438 /skills_load.`, "success");
        await this.pollLoad();
      } finally {
        cancellation.abort();
        if (form)
          await this.bridge.cancel(sessionID, form.id);
        this.loginFlow = null;
      }
    })(), sessionID);
  }
  async skills(sessionID, reload) {
    if (this.forms.has(sessionID))
      throw new Error("\u0424\u043E\u0440\u043C\u0430 \u0432\u044B\u0431\u043E\u0440\u0430 skills \u0443\u0436\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u0430");
    const accountGeneration = this.authGeneration;
    const token = this.authenticated() ? await this.apiToken() : null;
    let catalog = [];
    if (token) {
      const { data } = await this.api.request("/api/skills", { token, signal: this.abort.signal });
      catalog = validateCatalog(data);
    }
    const community = communityCatalog(this.options.client);
    if (!catalog.length && !community.length)
      return this.bridge.message(sessionID, "Skills", "\u041D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 skills.");
    const form = await this.bridge.form(sessionID, "\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C skills \u0438 \u043F\u043B\u0430\u0433\u0438\u043D\u044B", [{
      type: "multiselect",
      key: "skills",
      title: "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u043D\u0443\u0436\u043D\u044B\u0435 \u043F\u0430\u043A\u0435\u0442\u044B",
      description: "Community \u043F\u0430\u043A\u0435\u0442\u044B \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B \u0431\u0435\u0437 /login. \u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills \u0432\u0438\u0434\u043D\u044B \u043F\u043E\u0441\u043B\u0435 \u0432\u0445\u043E\u0434\u0430. \u0423\u0436\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u044B\u0435 \u043F\u0430\u043A\u0435\u0442\u044B \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u044E\u0442\u0441\u044F.",
      custom: false,
      minItems: 0,
      default: [],
      options: [
        ...community.map((item) => ({ value: item.id, label: `${item.name} \xB7 ${item.kind} \xB7 ${item.version}`, description: item.description })),
        ...catalog.map((skill) => ({ value: skill.id, label: `${skill.name} \xB7 corporate \xB7 ${skill.version}`, description: skill.description }))
      ]
    }]);
    const controller = new AbortController;
    this.forms.set(sessionID, { form, controller });
    this.track((async () => {
      try {
        const signal = AbortSignal.any([this.abort.signal, controller.signal, AbortSignal.timeout(300000)]);
        const answer = await this.bridge.wait(sessionID, form.id, signal);
        if (answer === null)
          return;
        const installed = await this.queue(async () => {
          if (token && (this.authGeneration !== accountGeneration || !this.authenticated()))
            throw new Error("\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0430\u0441\u044C; \u043E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /skills_load \u0441\u043D\u043E\u0432\u0430");
          const chosen = answer.skills ?? [];
          if (!Array.isArray(chosen) || new Set(chosen).size !== chosen.length)
            throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440 skills");
          const known = new Set([...community.map((item) => item.id), ...catalog.map((item) => item.id)]);
          if (chosen.some((id) => !known.has(id)))
            throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D skill \u0432\u043D\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0433\u043E \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430");
          const communityIDs = chosen.filter((id) => id.startsWith("community-"));
          const corporateIDs = chosen.filter((id) => id.startsWith("corp-"));
          const added = await installCommunity({ ids: communityIDs, client: this.options.client, skillsDir: this.options.skillsDir, configPath: this.options.configPath });
          const corporate = corporateIDs.length ? await installSkills({ ids: corporateIDs, catalog, api: this.api, token: await this.apiToken(), skillsDir: this.options.skillsDir, signal }) : [];
          return [...added, ...corporate];
        });
        await reload();
        await this.bridge.message(sessionID, "Skills \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D\u044B", installed.length ? installed.join(`
`) : "\u041D\u0438\u0447\u0435\u0433\u043E \u043D\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u043E.");
      } finally {
        this.forms.delete(sessionID);
        await this.bridge.cancel(sessionID, form.id);
      }
    })(), sessionID);
  }
  async mcps(sessionID, reload = async () => {}) {
    if (this.forms.has(sessionID))
      throw new Error("\u0424\u043E\u0440\u043C\u0430 \u0432\u044B\u0431\u043E\u0440\u0430 \u0443\u0436\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u0430");
    await this.apiToken();
    const accountGeneration = this.authGeneration;
    const catalog = await this.refreshMCPCatalog();
    if (!catalog.length)
      return this.options.client === "kilo" ? this.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP", "\u0414\u043B\u044F \u0432\u0430\u0448\u0435\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 MCP.") : this.notice("\u0414\u043B\u044F \u0432\u0430\u0448\u0435\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 MCP.", "info");
    const selected = this.mcpConfigs.map(({ name }) => name.slice(5));
    const form = await this.bridge.form(sessionID, "\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP", [{
      type: "multiselect",
      key: "mcps",
      title: "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 MCP",
      description: `\u0414\u043B\u044F \u043E\u0442\u043C\u0435\u0447\u0435\u043D\u043D\u044B\u0445 MCP \u043E\u0442\u043A\u0440\u043E\u0435\u0442\u0441\u044F \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u0430\u044F \u0444\u043E\u0440\u043C\u0430 \u0432\u0432\u043E\u0434\u0430 \u0438\u043B\u0438 \u0437\u0430\u043C\u0435\u043D\u044B \u0442\u043E\u043A\u0435\u043D\u043E\u0432, \u043D\u0435 \u0432 \u0447\u0430\u0442\u0435 ${this.options.client === "kilo" ? "Kilo" : "OpenCode"}.`,
      custom: false,
      minItems: 0,
      default: selected,
      options: catalog.map((item) => ({ value: item.id, label: item.name, description: item.description }))
    }]);
    const controller = new AbortController;
    this.forms.set(sessionID, { form, controller });
    this.track((async () => {
      try {
        const signal = AbortSignal.any([this.abort.signal, controller.signal, AbortSignal.timeout(300000)]);
        const answer = await this.bridge.wait(sessionID, form.id, signal);
        if (answer === null)
          return;
        const ids = answer.mcps ?? [];
        const requested = ids.map((id) => {
          const item = catalog.find((entry) => entry.id === id);
          if (!item)
            throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D MCP \u0432\u043D\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0433\u043E \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430");
          return item;
        });
        const apply = async (tokens) => {
          await this.queue(async () => {
            if (signal.aborted || this.authGeneration !== accountGeneration || !this.authenticated())
              throw new Error("\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0430\u0441\u044C; \u043E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /mcps_load \u0441\u043D\u043E\u0432\u0430");
            this.mcpConfigs = await saveMCPSelection(this.options.stateDir, ids, catalog, tokens);
            await this.reloadMCP();
          });
          await reload();
          if (!ids.length) {
            if (this.options.client === "kilo")
              await this.bridge.message(sessionID, "MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B", "\u0412\u0441\u0435 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B.");
            else
              await this.notice("\u0412\u0441\u0435 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B.", "info");
            return { kind: "success", title: "MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B", message: "\u0412\u0441\u0435 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B." };
          }
          let states = null;
          try {
            states = await this.mcpConnectionStates(ids);
          } catch {}
          const items = requested.map((item) => {
            const state = states?.find((entry) => entry.id === item.id);
            return { name: item.name, status: state?.status ?? "pending", detail: state?.status === "connected" ? "\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D" : state?.rejected ? "\u0422\u043E\u043A\u0435\u043D \u043E\u0442\u043A\u043B\u043E\u043D\u0451\u043D (HTTP 401)" : state?.status === "failed" ? "\u0421\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u043D\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043E" : "\u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435 \u0432 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0438" };
          });
          const failed = items.filter((item) => item.status !== "connected");
          if (states && failed.length) {
            const summary = failed.map((item) => `${item.name}: ${item.detail}`).join("; ");
            if (this.options.client === "kilo")
              await this.bridge.message(sessionID, "MCP \u043D\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u044B", summary);
            else
              await this.notice(`MCP \u043D\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u044B. ${summary}`, "warning");
            return { kind: "error", title: "\u041D\u0435 \u0432\u0441\u0435 MCP \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u043B\u0438\u0441\u044C", message: "\u041D\u0430\u0441\u0442\u0440\u043E\u0439\u043A\u0438 \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u044B. \u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 /mcps_load, \u0447\u0442\u043E\u0431\u044B \u0437\u0430\u043C\u0435\u043D\u0438\u0442\u044C \u0442\u043E\u043A\u0435\u043D\u044B.", items };
          }
          const names = requested.map((item) => item.name).join(", ");
          if (this.options.client === "kilo")
            await this.bridge.message(sessionID, "MCP \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B", names);
          else
            await this.notice(`${states ? "MCP \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u044B" : "MCP \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B \u0432 \u043A\u043E\u043D\u0444\u0438\u0433"}: ${names}`, "success");
          return { kind: states ? "success" : "warning", title: states ? "MCP \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u044B" : "MCP \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u044B \u0432 \u043A\u043E\u043D\u0444\u0438\u0433", message: states ? "\u0421\u0438\u0441\u0442\u0435\u043C\u044B \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B \u0432 OpenCode." : "\u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u0435 \u0432 Kilo.", items };
        };
        if (requested.length) {
          const page2 = await captureSecrets(requested, { onSubmit: apply });
          const cancel = () => page2.cancel();
          signal.addEventListener("abort", cancel, { once: true });
          let notice;
          try {
            if (process.env.CORP_NO_BROWSER === "1")
              notice = await this.bridge.form(sessionID, "\u0422\u043E\u043A\u0435\u043D\u044B \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0445 MCP", [{ type: "external", key: "tokens", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u0443\u044E \u0444\u043E\u0440\u043C\u0443 \u0434\u043B\u044F \u0442\u043E\u043A\u0435\u043D\u043E\u0432", url: page2.url }]);
            else
              await this.open(page2.url).catch(async () => {
                notice = await this.bridge.form(sessionID, "\u0422\u043E\u043A\u0435\u043D\u044B \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0445 MCP", [{ type: "external", key: "tokens", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u0443\u044E \u0444\u043E\u0440\u043C\u0443 \u0434\u043B\u044F \u0442\u043E\u043A\u0435\u043D\u043E\u0432", url: page2.url }]);
              });
            await page2.result;
          } finally {
            signal.removeEventListener("abort", cancel);
            page2.cancel();
            if (notice)
              await this.bridge.cancel(sessionID, notice.id);
          }
        } else
          await apply(new Map);
      } finally {
        this.forms.delete(sessionID);
        await this.bridge.cancel(sessionID, form.id);
      }
    })(), sessionID, false);
  }
  async logout() {
    this.authGeneration++;
    this.loginFlow?.cancel();
    for (const { controller } of this.forms.values())
      controller.abort();
    await this.queue(async () => {
      const refreshToken = this.credential?.refreshToken;
      const accessToken = this.credential?.accessToken;
      await this.invalidate();
      this.state = {};
      await this.persistState();
      this.load = { level: "unknown", message: "\u0412\u0445\u043E\u0434 \u043D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", checkedAt: null };
      try {
        await this.configWrites(() => this.removeProvider(this.options.configPath, this.options.client));
      } finally {
        if (refreshToken) {
          try {
            await this.api.request("/oauth/revoke", { method: "POST", body: { refreshToken } });
          } catch {
            if (accessToken)
              await this.api.request("/oauth/revoke", { method: "POST", token: accessToken, body: {} }).catch(() => {});
          }
        } else if (accessToken)
          await this.api.request("/oauth/revoke", { method: "POST", token: accessToken, body: {} }).catch(() => {});
      }
    });
  }
  dispose() {
    clearInterval(this.configTimer);
    clearInterval(this.loadTimer);
    clearTimeout(this.tokenTimer);
    this.abort.abort();
    this.loginFlow?.cancel();
    clearMCPEnv(this.options.stateDir);
  }
}
function optionsFromEnv(env = process.env, settings = {}) {
  const client = settings.client === "kilo" ? "kilo" : "opencode";
  const profile = resolve((client === "kilo" ? env.CORP_KILO_PROFILE_DIR : undefined) ?? env.CORP_PROFILE_DIR ?? settings.profileDir ?? (client === "kilo" ? env.KILO_CONFIG_DIR : env.OPENCODE_CONFIG_DIR) ?? join5(env.XDG_CONFIG_HOME ?? join5(homedir(), ".config"), client));
  const serviceFile = join5(env.XDG_STATE_HOME ?? join5(homedir(), ".local", "state"), "opencode", "service.json");
  const interval = (value, fallback) => {
    const n = Number(value ?? fallback);
    if (!Number.isFinite(n) || n < 50)
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0432\u0430\u043B \u043E\u043F\u0440\u043E\u0441\u0430");
    return n;
  };
  return {
    client,
    serverURL: trustedURL(env.CORP_SERVER_URL ?? settings.serverURL ?? "http://127.0.0.1:4310"),
    configPath: join5(profile, client === "kilo" ? "kilo.jsonc" : "opencode.jsonc"),
    stateDir: join5(profile, "corporate-state"),
    skillsDir: join5(profile, "skills"),
    connectionFile: env.CORP_OPENCODE_CONNECTION_FILE ?? settings.connectionFile ?? serviceFile,
    refreshMs: interval(env.CORP_REFRESH_INTERVAL_MS ?? settings.refreshMs, 3600000),
    loadPollMs: interval(env.CORP_LOAD_INTERVAL_MS ?? settings.loadPollMs, 30000)
  };
}

// src/kilo-control.js
import { createServer as createServer3 } from "http";
import { timingSafeEqual as timingSafeEqual2 } from "crypto";
import { rmSync } from "fs";
import { join as join6 } from "path";

// src/kilo-bridge.js
import { createServer as createServer2 } from "http";
var escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

class KiloBridge {
  constructor(toast = () => {}, open2 = openBrowser) {
    this.toast = toast;
    this.open = open2;
    this.forms = new Map;
  }
  async form(_sessionID, title, fields) {
    const id = random();
    const field = fields.find((item) => item.type === "multiselect");
    if (!field)
      return { id };
    const options = new Map(field.options.map((item) => [item.value, item]));
    let accept;
    const result = new Promise((resolve2) => {
      accept = resolve2;
    });
    const server = createServer2(async (request, response) => {
      const url2 = `http://127.0.0.1:${server.address().port}/form/${id}`;
      const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
      if (request.url !== `/form/${id}` || request.headers.host !== `127.0.0.1:${server.address().port}`) {
        response.writeHead(404, headers).end();
        return;
      }
      if (request.method === "GET") {
        const choices = field.options.map((item) => `<label><input type="checkbox" name="choice" value="${escape(item.value)}" ${field.default?.includes(item.value) ? "checked" : ""}><span><b>${escape(item.label)}</b><small>${escape(item.description ?? "")}</small></span></label>`).join("");
        const html = `<!doctype html><html lang="ru"><meta charset="utf-8"><title>${escape(title)}</title><style>body{font:16px system-ui;background:#f7f7f4;color:#222;max-width:620px;margin:6vh auto;padding:24px}h1{font-size:24px}label{display:flex;gap:12px;padding:14px;margin:10px 0;background:white;border:1px solid #ddd;border-radius:10px}small{display:block;color:#666;margin-top:4px}button{background:#222;color:white;border:0;border-radius:8px;padding:12px 20px;cursor:pointer}</style><h1>${escape(title)}</h1><p>${escape(field.description ?? "")}</p><form method="post">${choices}<button>\u041F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C</button></form></html>`;
        response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(html);
        return;
      }
      if (request.method !== "POST" || request.headers.origin !== new URL(url2).origin || !request.headers["content-type"]?.startsWith("application/x-www-form-urlencoded")) {
        response.writeHead(403, headers).end();
        return;
      }
      let body = "";
      for await (const chunk of request) {
        body += chunk;
        if (body.length > 65536) {
          response.writeHead(413, headers).end();
          return;
        }
      }
      const values = new URLSearchParams(body).getAll("choice");
      if (new Set(values).size !== values.length || values.some((value) => !options.has(value))) {
        response.writeHead(400, headers).end();
        return;
      }
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<!doctype html><html lang=ru><meta charset=utf-8><p>\u0412\u044B\u0431\u043E\u0440 \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D. \u042D\u0442\u0443 \u0432\u043A\u043B\u0430\u0434\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u0437\u0430\u043A\u0440\u044B\u0442\u044C.</p></html>");
      accept({ [field.key]: values });
      server.close();
    });
    await new Promise((resolve2, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve2);
    });
    const url = `http://127.0.0.1:${server.address().port}/form/${id}`;
    this.forms.set(id, { server, result, accept });
    this.open(url).catch(() => this.toast({ title, message: `\u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 ${url}`, variant: "info", duration: 15000 }));
    return { id, url };
  }
  async message(_sessionID, title, description) {
    this.toast({ title, message: description, variant: "info", duration: 1e4 });
  }
  wait(_sessionID, id, signal) {
    const form = this.forms.get(id);
    if (!form)
      return signal?.aborted ? Promise.resolve(undefined) : new Promise((resolve2) => signal?.addEventListener("abort", () => resolve2(undefined), { once: true }));
    if (signal?.aborted)
      return Promise.resolve(null);
    return Promise.race([form.result, new Promise((resolve2) => signal?.addEventListener("abort", () => resolve2(null), { once: true }))]);
  }
  async cancel(_sessionID, id) {
    const form = this.forms.get(id);
    if (!form)
      return;
    this.forms.delete(id);
    form.accept(null);
    form.server.close();
  }
  dispose() {
    for (const id of this.forms.keys())
      this.cancel(null, id);
  }
}

// src/commands.js
var commands = Object.freeze([
  { name: "login", description: "\u0412\u043E\u0439\u0442\u0438 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode \u0447\u0435\u0440\u0435\u0437 \u0431\u0440\u0430\u0443\u0437\u0435\u0440", kiloDescription: "\u0412\u043E\u0439\u0442\u0438 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0435\u0440\u0432\u0438\u0441", reload: true },
  { name: "refresh_config", description: "\u041F\u043E\u043B\u0443\u0447\u0438\u0442\u044C \u0438 \u043F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433", kiloDescription: "\u041E\u0431\u043D\u043E\u0432\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433", reload: true },
  { name: "skills_load", description: "\u0412\u044B\u0431\u0440\u0430\u0442\u044C community skills, \u043F\u043B\u0430\u0433\u0438\u043D\u044B \u0438 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", kiloDescription: "\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C skills \u0438\u0437 \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430", reload: true },
  { name: "mcps_load", description: "\u0412\u044B\u0431\u0440\u0430\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u0438 \u0432\u0432\u0435\u0441\u0442\u0438 \u043B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B", kiloDescription: "\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP", reload: true },
  { name: "logout", description: "\u0412\u044B\u0439\u0442\u0438 \u0438\u0437 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u043E\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438", kiloDescription: "\u0412\u044B\u0439\u0442\u0438 \u0438\u0437 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u043E\u0433\u043E \u0441\u0435\u0440\u0432\u0438\u0441\u0430", reload: true },
  { name: "corp_status", description: "\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C, \u0432\u0435\u0440\u0441\u0438\u044F \u043A\u043E\u043D\u0444\u0438\u0433\u0430 \u0438 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441\u0430", kiloDescription: "\u041F\u043E\u043A\u0430\u0437\u0430\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0442\u0430\u0442\u0443\u0441", reload: false },
  { name: "inference_status", description: "\u0421\u0432\u0435\u0442\u043E\u0444\u043E\u0440 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438 \u043D\u0430 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441", kiloDescription: "\u041F\u043E\u043A\u0430\u0437\u0430\u0442\u044C \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0443 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441\u0430", reload: false }
]);
var commandByName = new Map(commands.map((command) => [command.name, command]));
async function runOpenCodeCommand(runtime, context, name, sessionID) {
  switch (name) {
    case "login":
      return runtime.login(sessionID);
    case "refresh_config": {
      const state = await runtime.refresh();
      return runtime.bridge.message(sessionID, "\u041A\u043E\u043D\u0444\u0438\u0433 \u0430\u043A\u0442\u0443\u0430\u043B\u0435\u043D", `\u0412\u0435\u0440\u0441\u0438\u044F ${state.revision}. \u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D\u043E: ${state.checkedAt}`);
    }
    case "skills_load":
      return runtime.skills(sessionID, () => context.skill.reload());
    case "mcps_load":
      return runtime.mcps(sessionID);
    case "logout": {
      await runtime.logout();
      return runtime.bridge.message(sessionID, "\u0412\u044B\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", "\u0422\u043E\u043A\u0435\u043D \u0443\u0434\u0430\u043B\u0451\u043D, \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440 \u043E\u0442\u043A\u043B\u044E\u0447\u0451\u043D. \u0421\u043A\u0430\u0447\u0430\u043D\u043D\u044B\u0435 skills \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u044B.");
    }
    case "corp_status": {
      const status = runtime.status();
      return runtime.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0442\u0430\u0442\u0443\u0441", `${status.authenticated ? status.user.name : "\u041D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D \u0432\u0445\u043E\u0434 \u2014 /login"}
\u041A\u043E\u043D\u0444\u0438\u0433: ${status.config.revision ?? "\u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D"}
\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u044F\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0430: ${status.config.checkedAt ?? "\u0435\u0449\u0451 \u043D\u0435 \u0431\u044B\u043B\u043E"}
${lights[status.load.level]} ${status.load.message}
\u0410\u0432\u0442\u043E\u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435: ${status.refreshMinutes} \u043C\u0438\u043D.${status.config.lastError ? `
${status.config.lastError}` : ""}`);
    }
    case "inference_status": {
      await runtime.apiToken();
      await runtime.pollLoad();
      return runtime.bridge.message(sessionID, `${lights[runtime.load.level]} \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441`, runtime.load.message);
    }
    default:
      throw new Error("\u041D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u0430\u044F \u043A\u043E\u043C\u0430\u043D\u0434\u0430");
  }
}
function registerOpenCodeCommands(context, runtime) {
  return context.command.transform((registry) => {
    for (const { name, description } of commands)
      registry.add({ name, description, async execute({ sessionID }) {
        try {
          if (name !== "login" && name !== "skills_load" && !runtime.authenticated()) {
            await runtime.bridge.message(sessionID, `/${name}`, "\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 /login, \u0447\u0442\u043E\u0431\u044B \u0432\u043E\u0439\u0442\u0438 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode.");
            return;
          }
          await runOpenCodeCommand(runtime, context, name, sessionID);
        } catch (error) {
          await runtime.bridge.message(sessionID, `/${name}`, error.message);
        }
      } });
  });
}

// src/kilo-control.js
var key = Symbol.for("company.kilo.corporate.control.v6");
var legacyKeys = [Symbol.for("company.kilo.corporate.control.v5"), Symbol.for("company.kilo.corporate.control.v4"), Symbol.for("company.kilo.corporate.control.v3"), Symbol.for("company.kilo.corporate.control.v2"), Symbol.for("company.kilo.corporate.control.v1")];
async function startKiloControl(settings = {}, adapters = {}) {
  const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
  const name = `${options.configPath}|${options.serverURL}`;
  for (const legacyKey of legacyKeys) {
    const legacy = globalThis[legacyKey];
    if (!legacy?.has(name))
      continue;
    const previous = await legacy.get(name).catch(() => null);
    legacy.delete(name);
    previous?.runtime.dispose();
    previous?.bridge.dispose();
    previous?.server.closeAllConnections();
    previous?.server.close();
  }
  const registry = globalThis[key] ??= new Map;
  if (registry.has(name))
    return registry.get(name);
  const ready = boot(options, adapters).catch((error) => {
    registry.delete(name);
    throw error;
  });
  registry.set(name, ready);
  return ready;
}
async function boot(options, adapters) {
  let messages = [];
  const bridge = new KiloBridge(({ title, message }) => messages.push(`${title}: ${message}`), adapters.open);
  const runtime = new CorporateRuntime(options, {
    bridge,
    open: adapters.open,
    notify: adapters.notify,
    reloadProvider: adapters.reloadProvider,
    syncMCP: (configs) => syncKiloMCP(options.configPath, options.stateDir, configs)
  });
  await runtime.start();
  const secret = random();
  const queue = serial();
  const execute = (command) => queue(async () => {
    messages = [];
    if (command !== "login" && command !== "skills_load" && !runtime.authenticated())
      return { message: "\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 /login.", reload: false };
    if (command === "login")
      await runtime.login("kilo-vscode");
    if (command === "refresh_config") {
      const state = await runtime.refresh();
      await bridge.message(null, "\u041A\u043E\u043D\u0444\u0438\u0433 \u0430\u043A\u0442\u0443\u0430\u043B\u0435\u043D", `\u0412\u0435\u0440\u0441\u0438\u044F ${state.revision}. \u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D\u043E: ${state.checkedAt}`);
    }
    if (command === "skills_load")
      await runtime.skills("kilo-vscode", async () => {});
    if (command === "mcps_load")
      await runtime.mcps("kilo-vscode");
    if (command === "logout") {
      await runtime.logout();
      await bridge.message(null, "\u0412\u044B\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0438 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440 \u0443\u0434\u0430\u043B\u0435\u043D\u044B.");
    }
    if (command === "corp_status") {
      const status = runtime.status();
      await bridge.message(null, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0442\u0430\u0442\u0443\u0441", `${status.user.name}
\u041A\u043E\u043D\u0444\u0438\u0433: ${status.config.revision ?? "\u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D"}
${lights[status.load.level]} ${status.load.message}`);
    }
    if (command === "inference_status") {
      await runtime.pollLoad();
      await bridge.message(null, `${lights[runtime.load.level]} \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441`, runtime.load.message);
    }
    const jobs = await Promise.allSettled([...runtime.jobs]);
    const failure = jobs.find((item) => item.status === "rejected");
    if (failure)
      throw failure.reason;
    return { message: messages.at(-1) ?? "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0430.", reload: commandByName.get(command).reload };
  });
  const server = createServer3(async (request, response) => {
    const port = server.address().port;
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Type": "application/json; charset=utf-8" };
    const credential = Buffer.from(request.headers.authorization?.replace(/^Bearer /, "") ?? "");
    const expected = Buffer.from(secret);
    if (request.headers.host !== `127.0.0.1:${port}` || request.headers.origin || credential.length !== expected.length || !timingSafeEqual2(credential, expected)) {
      response.writeHead(403, headers).end(JSON.stringify({ error: "Forbidden" }));
      return;
    }
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, headers).end(JSON.stringify({ ok: true }));
      return;
    }
    const command = request.url?.match(/^\/command\/([a-z_]+)$/)?.[1];
    if (request.method !== "POST" || !commandByName.has(command)) {
      response.writeHead(404, headers).end(JSON.stringify({ error: "Unknown command" }));
      return;
    }
    try {
      const result = await execute(command);
      response.writeHead(200, headers).end(JSON.stringify(result));
    } catch (error) {
      response.writeHead(500, headers).end(JSON.stringify({ error: error.message ?? "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u043D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0430" }));
    }
  });
  try {
    await new Promise((resolve2, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve2);
    });
    server.unref();
    const state = JSON.stringify({ port: server.address().port, secret });
    const ownFile = join6(options.stateDir, `control-${process.pid}.json`);
    server.on("close", () => {
      try {
        rmSync(ownFile, { force: true });
      } catch {}
    });
    process.once("exit", () => {
      try {
        rmSync(ownFile, { force: true });
      } catch {}
    });
    await atomicWrite(ownFile, state);
    await atomicWrite(join6(options.stateDir, "control.json"), state);
    runtime.autoLogin();
    return { runtime, server, bridge };
  } catch (error) {
    server.close();
    runtime.dispose();
    bridge.dispose();
    throw error;
  }
}

// src/kilo-workflows.js
import { readFile as readFile5 } from "fs/promises";
import { dirname as dirname3, join as join7 } from "path";
var marker = "# opencode_corp managed Kilo workflow";
var legacyMarker = "<!-- opencode_corp managed Kilo workflow -->";
var helper = String.raw`import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const names = new Set(${JSON.stringify(commands.map(({ name }) => name))});
const name = process.argv[2];
if (!names.has(name)) throw new Error("\u041D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u0430\u044F \u043A\u043E\u043C\u0430\u043D\u0434\u0430");
const directory = dirname(fileURLToPath(import.meta.url));
const files = (await readdir(directory)).filter((file) => /^control-\d+\.json$/.test(file));
files.sort((a, b) => Number(b.match(/\d+/)[0]) - Number(a.match(/\d+/)[0]));
files.unshift("control.json");

async function active(file) {
  try {
    const path = join(directory, file);
    if ((await stat(path)).mode & 0o077) return;
    const state = JSON.parse(await readFile(path, "utf8"));
    if (!Number.isInteger(state.port) || state.port < 1 || state.port > 65535 ||
      typeof state.secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(state.secret)) return;
    const response = await fetch("http://127.0.0.1:" + state.port + "/health", {
      headers: { Authorization: "Bearer " + state.secret }, signal: AbortSignal.timeout(1000),
    });
    if (response.ok) return state;
  } catch {}
}

let control;
for (const file of files) {
  control = await active(file);
  if (control) break;
}
if (!control) throw new Error("\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043F\u043B\u0430\u0433\u0438\u043D Kilo \u043D\u0435 \u0437\u0430\u043F\u0443\u0449\u0435\u043D");
const response = await fetch("http://127.0.0.1:" + control.port + "/command/" + name, {
  method: "POST", headers: { Authorization: "Bearer " + control.secret },
  signal: AbortSignal.timeout(310000),
});
const result = await response.json();
if (!response.ok) throw new Error(result.error || "\u041A\u043E\u043C\u0430\u043D\u0434\u0430 \u043D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0430");
if (typeof result.message !== "string") throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043E\u0442\u0432\u0435\u0442 \u043F\u043B\u0430\u0433\u0438\u043D\u0430");
console.log(result.message);
`;
function quote(path) {
  if (/[\r\n`]/.test(path))
    throw new Error("\u041D\u0435\u0434\u043E\u043F\u0443\u0441\u0442\u0438\u043C\u044B\u0439 \u043F\u0443\u0442\u044C \u043A \u043A\u043E\u043D\u0444\u0438\u0433\u0443 Kilo");
  return `'${path.replaceAll("'", `'"'"'`)}'`;
}
async function installKiloWorkflows(options) {
  const script = join7(options.stateDir, "workflow-command.mjs");
  await atomicWrite(script, helper);
  const conflicts = [];
  for (const { name, kiloDescription: description } of commands) {
    const file = join7(dirname3(options.configPath), "commands", `${name}.md`);
    const current = await exists(file);
    if (current) {
      if (current.isSymbolicLink()) {
        conflicts.push(name);
        continue;
      }
      const content2 = await readFile5(file, "utf8");
      if (!content2.includes(marker) && !content2.includes(legacyMarker)) {
        conflicts.push(name);
        continue;
      }
    }
    const content = `---
${marker}
description: ${description}
---

\u0412\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u043D\u0430\u044F \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u0430\u044F \u043A\u043E\u043C\u0430\u043D\u0434\u0430 /${name} \u0432\u0435\u0440\u043D\u0443\u043B\u0430 \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442:

!\`node ${quote(script)} ${name}\`

\u041E\u0442\u0432\u0435\u0442\u044C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044E \u043A\u0440\u0430\u0442\u043A\u043E \u043F\u043E-\u0440\u0443\u0441\u0441\u043A\u0438, \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442 \u043A\u043E\u043C\u0430\u043D\u0434\u044B \u0432\u044B\u0448\u0435.
`;
    await atomicWrite(file, content);
  }
  return { conflicts };
}

// src/plugin.js
var rpc = {
  id: "company.corporate",
  methods: { status: { input: { type: "object", properties: {}, additionalProperties: false }, output: { type: "object" } } },
  events: { notice: { schema: { type: "object", properties: { message: { type: "string" }, level: { type: "string" }, at: { type: "number" } }, required: ["message", "level", "at"] } } }
};
var registryKey = Symbol.for("company.opencode.corporate.runtime.v9");
function release(registry, key2, entry) {
  if (--entry.refs !== 0)
    return;
  entry.runtime.dispose();
  if (registry.get(key2) === entry)
    registry.delete(key2);
}
var plugin_default = {
  id: "company-corporate",
  async server(_context, settings) {
    await startKiloControl(settings);
    const options = optionsFromEnv(process.env, { ...settings, client: "kilo" });
    const { conflicts } = await installKiloWorkflows(options);
    if (conflicts.length)
      console.warn(`\u0421\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u044E\u0449\u0438\u0435 Kilo workflows \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u044B: ${conflicts.join(", ")}`);
    return {};
  },
  async setup(context) {
    const options = optionsFromEnv(process.env, context.options);
    const registry = globalThis[registryKey] ??= new Map;
    const key2 = `${options.configPath}|${options.serverURL}`;
    let entry = registry.get(key2);
    if (!entry) {
      const runtime2 = new CorporateRuntime(options, { syncMCP: (configs) => syncOpenCodeMCP(options.configPath, options.stateDir, configs) });
      entry = { runtime: runtime2, ready: runtime2.start(), refs: 0 };
      registry.set(key2, entry);
    }
    entry.refs++;
    const runtime = entry.runtime;
    let mcpRegistration, rpcRegistration, reloadMCP, listener;
    try {
      await entry.ready;
      reloadMCP = () => context.mcp.reload();
      runtime.mcpReloaders.add(reloadMCP);
      mcpRegistration = await context.mcp.transform((editor) => {
        for (const [name] of editor.list())
          if (name.startsWith("corp_"))
            editor.remove(name);
        if (runtime.authenticated())
          for (const { name, config } of runtime.mcpConfigs) {
            const value = process.env[mcpEnvName(options.stateDir, name.slice(5))];
            if (value)
              editor.set(name, { ...config, headers: { Authorization: `Bearer ${value}` } });
          }
      });
      rpcRegistration = await context.rpc.register(rpc, { status: async () => runtime.status() });
      listener = (event) => rpcRegistration.events.emit("notice", event);
      runtime.listeners.add(listener);
      await registerOpenCodeCommands(context, runtime);
      if (!entry.autoLoginStarted) {
        entry.autoLoginStarted = true;
        runtime.autoLogin();
      }
    } catch (error) {
      runtime.mcpReloaders.delete(reloadMCP);
      if (listener)
        runtime.listeners.delete(listener);
      rpcRegistration?.dispose?.();
      mcpRegistration?.dispose?.();
      release(registry, key2, entry);
      throw error;
    }
    let disposed = false;
    return () => {
      if (disposed)
        return;
      disposed = true;
      runtime.mcpReloaders.delete(reloadMCP);
      mcpRegistration?.dispose?.();
      runtime.listeners.delete(listener);
      rpcRegistration.dispose?.();
      release(registry, key2, entry);
    };
  }
};
export {
  plugin_default as default
};
