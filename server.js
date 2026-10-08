// @bun
// src/runtime.js
import { join as join4, resolve } from "path";
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
import { join } from "path";
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
function parseConfig(text) {
  const errors = [];
  const value = parse2(text, errors, { allowTrailingComma: true });
  if (errors.length || !object(value))
    throw new Error("opencode.jsonc \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u0442 \u043E\u0448\u0438\u0431\u043A\u0443; \u0444\u0430\u0439\u043B \u043D\u0435 \u0438\u0437\u043C\u0435\u043D\u0451\u043D");
  return value;
}
async function applyConfig({ configPath, stateDir, envelope, serverURL, previous }) {
  const clean = validateConfig(envelope, serverURL);
  const fingerprint = digest(JSON.stringify(clean));
  if (previous && clean.revision < previous.revision)
    throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u043F\u0440\u0438\u0441\u043B\u0430\u043B \u0431\u043E\u043B\u0435\u0435 \u0441\u0442\u0430\u0440\u0443\u044E \u0432\u0435\u0440\u0441\u0438\u044E \u043A\u043E\u043D\u0444\u0438\u0433\u0430");
  if (previous?.revision === clean.revision && previous.fingerprint !== fingerprint)
    throw new Error("\u0421\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0435 \u043A\u043E\u043D\u0444\u0438\u0433\u0430 \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u043E\u0441\u044C \u0431\u0435\u0437 \u0443\u0432\u0435\u043B\u0438\u0447\u0435\u043D\u0438\u044F \u0432\u0435\u0440\u0441\u0438\u0438");
  let text = await readFile2(configPath, "utf8");
  const current = parseConfig(text);
  const provider = {
    ...clean.config.providers.corporate,
    package: "@ai-sdk/openai-compatible",
    settings: { ...clean.config.providers.corporate.settings, apiKey: `{file:${join(stateDir, "access-token")}}` }
  };
  const changed = JSON.stringify(current.providers?.corporate) !== JSON.stringify(provider);
  if (changed) {
    const backup = `${configPath}.before-corporate.bak`;
    if (!await exists(backup))
      await atomicWrite(backup, text);
    text = applyEdits(text, modify(text, ["providers", "corporate"], provider, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
    parseConfig(text);
    await atomicWrite(configPath, text);
  }
  return { revision: clean.revision, fingerprint, changed, checkedAt: new Date().toISOString() };
}
async function removeProvider(configPath) {
  let text = await readFile2(configPath, "utf8");
  const current = parseConfig(text);
  if (!object(current.providers))
    return;
  const count = Object.keys(current.providers).length;
  if (!Object.hasOwn(current.providers, "corporate") && count > 0)
    return;
  const path = count <= 1 ? ["providers"] : ["providers", "corporate"];
  text = applyEdits(text, modify(text, path, undefined, {}));
  parseConfig(text);
  await atomicWrite(configPath, text);
}

// src/skills.js
import { mkdir as mkdir2, readFile as readFile3 } from "fs/promises";
import { join as join2 } from "path";
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
    const directory = join2(skillsDir, skill.id);
    if ((await exists(directory))?.isSymbolicLink())
      throw new Error("\u041E\u0442\u043A\u0430\u0437 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438 \u0447\u0435\u0440\u0435\u0437 \u0441\u0438\u043C\u0432\u043E\u043B\u0438\u0447\u0435\u0441\u043A\u0443\u044E \u0441\u0441\u044B\u043B\u043A\u0443");
    const target = join2(directory, "SKILL.md");
    const marker = join2(directory, ".corporate-sha256");
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

// src/mcp.js
import { readFile as readFile4, rm, lstat as lstat2, readdir } from "fs/promises";
import { join as join3 } from "path";
var idPattern = /^[a-z][a-z0-9_-]{0,39}$/;
var text = (value, max = 200) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
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
async function readMCPState(stateDir, catalog) {
  let selected;
  try {
    selected = JSON.parse(await readFile4(join3(stateDir, "mcp-selection.json"), "utf8"));
  } catch (error) {
    if (error.code === "ENOENT")
      return [];
    throw error;
  }
  if (!Array.isArray(selected))
    return [];
  const allowed = selected.filter((id) => catalog.some((entry) => entry.id === id));
  const configurations = [];
  for (const id of allowed) {
    const entry = catalog.find((item) => item.id === id);
    let token;
    try {
      const path = join3(stateDir, "mcp-tokens", id);
      if (!(await lstat2(path)).isFile())
        continue;
      token = await readFile4(path, "utf8");
    } catch (error) {
      if (error.code === "ENOENT")
        continue;
      throw error;
    }
    if (!token || token.length > 512 || /[\r\n]/.test(token))
      continue;
    configurations.push({ name: `corp_${id}`, config: { type: "remote", url: entry.url, oauth: false, headers: { Authorization: `Bearer ${token}` } } });
  }
  return configurations;
}
async function saveMCPSelection(stateDir, ids, catalog, tokens) {
  validateSelection(ids, catalog);
  for (const id of ids) {
    const token = tokens.get(id);
    if (token !== undefined) {
      if (!text(token, 512) || /[\r\n]/.test(token))
        throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u043B\u0438\u0447\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D MCP");
      await atomicWrite(join3(stateDir, "mcp-tokens", id), token);
    }
  }
  await atomicWrite(join3(stateDir, "mcp-selection.json"), JSON.stringify(ids));
  const tokenDir = join3(stateDir, "mcp-tokens");
  for (const name of await readdir(tokenDir).catch((error) => {
    if (error.code === "ENOENT")
      return [];
    throw error;
  })) {
    if (!ids.includes(name))
      await rm(join3(tokenDir, name), { force: true });
  }
  return readMCPState(stateDir, catalog);
}
async function clearMCP(stateDir) {
  await Promise.all([
    rm(join3(stateDir, "mcp-selection.json"), { force: true }),
    rm(join3(stateDir, "mcp-tokens"), { force: true, recursive: true })
  ]);
}

// src/secret-page.js
import { createServer } from "http";
async function captureSecret(title, { timeoutMs = 300000 } = {}) {
  const nonce = random();
  let settled = false;
  let accept, reject;
  const result = new Promise((yes, no) => {
    accept = yes;
    reject = no;
  });
  const server = createServer((request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const path = `/secret/${nonce}`;
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
    if (request.url !== path || request.headers.host !== `127.0.0.1:${server.address().port}`) {
      response.writeHead(404).end();
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" });
      response.end(`<html lang="ru"><meta charset="utf-8"><title>${escapeHTML(title)}</title><style>body{font:16px system-ui;max-width:32rem;margin:4rem auto;padding:1rem}input,button{font:inherit;padding:.6rem}input{width:100%;box-sizing:border-box;margin:1rem 0}</style><h1>${escapeHTML(title)}</h1><p>\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0442\u043E\u043A\u0435\u043D. \u041E\u043D \u0431\u0443\u0434\u0435\u0442 \u0441\u043E\u0445\u0440\u0430\u043D\u0451\u043D \u0442\u043E\u043B\u044C\u043A\u043E \u043D\u0430 \u044D\u0442\u043E\u043C \u043A\u043E\u043C\u043F\u044C\u044E\u0442\u0435\u0440\u0435 \u0438 \u043D\u0435 \u043F\u043E\u043F\u0430\u0434\u0451\u0442 \u0432 \u0447\u0430\u0442. \u0414\u043B\u044F \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u0433\u043E \u044D\u043C\u0443\u043B\u044F\u0442\u043E\u0440\u0430 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 \u0442\u043E\u043B\u044C\u043A\u043E \u0442\u0435\u0441\u0442\u043E\u0432\u044B\u0439 \u0442\u043E\u043A\u0435\u043D \u0438\u0437 \u043E\u043F\u0438\u0441\u0430\u043D\u0438\u044F MCP, \u043D\u0435 \u043D\u0430\u0441\u0442\u043E\u044F\u0449\u0438\u0439 Jira/Confluence PAT.</p><form method="post" action="${path}"><input type="password" name="token" autocomplete="off" required autofocus><button>\u041F\u0435\u0440\u0435\u0434\u0430\u0442\u044C \u043F\u043B\u0430\u0433\u0438\u043D\u0443</button></form>`);
      return;
    }
    if (request.method !== "POST" || request.headers.origin !== origin || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") {
      response.writeHead(403, headers).end();
      return;
    }
    let input = "";
    request.on("data", (chunk) => {
      input += chunk;
      if (input.length > 2048)
        request.destroy();
    });
    request.on("end", () => {
      const token = new URLSearchParams(input).get("token");
      if (!token || token.length > 512 || /[\r\n]/.test(token)) {
        response.writeHead(400, headers).end("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D");
        return;
      }
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<html lang=ru><meta charset=utf-8><p>\u0422\u043E\u043A\u0435\u043D \u043F\u0435\u0440\u0435\u0434\u0430\u043D \u043F\u043B\u0430\u0433\u0438\u043D\u0443. \u042D\u0442\u0443 \u0432\u043A\u043B\u0430\u0434\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u0437\u0430\u043A\u0440\u044B\u0442\u044C.</p>");
      if (!settled) {
        settled = true;
        accept(token);
        server.close();
      }
    });
  });
  await new Promise((resolve, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", resolve);
  });
  const timer = setTimeout(() => {
    if (!settled) {
      settled = true;
      reject(new Error("\u0412\u0440\u0435\u043C\u044F \u0432\u0432\u043E\u0434\u0430 \u0442\u043E\u043A\u0435\u043D\u0430 \u0438\u0441\u0442\u0435\u043A\u043B\u043E"));
      server.close();
    }
  }, timeoutMs);
  timer.unref();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return { url: `http://127.0.0.1:${server.address().port}/secret/${nonce}`, result, cancel: () => {
    if (!settled) {
      settled = true;
      reject(new Error("\u0412\u0432\u043E\u0434 \u0442\u043E\u043A\u0435\u043D\u0430 \u043E\u0442\u043C\u0435\u043D\u0451\u043D"));
      server.close();
    }
  } };
}

// src/login.js
import { createHash as createHash2, timingSafeEqual } from "crypto";
async function startLogin(api, { timeoutMs = 300000 } = {}) {
  const state = random();
  const verifier = random();
  const challenge = createHash2("sha256").update(verifier).digest("base64url");
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
        return new Response("\u0412\u0445\u043E\u0434 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043D. \u0412\u0435\u0440\u043D\u0438\u0442\u0435\u0441\u044C \u0432 OpenCode.", { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
      } catch (error) {
        reject(error);
        return new Response("\u0412\u0445\u043E\u0434 \u043D\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0451\u043D. \u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u0435 /login \u0432 OpenCode.", { status: 400 });
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
var validCredential = (value) => value && typeof value.accessToken === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value.accessToken) && Number.isFinite(value.expiresAt) && typeof value.user?.name === "string";

class CorporateRuntime {
  constructor(options, adapters = {}) {
    this.options = options;
    this.api = adapters.api ?? new CorporateAPI(options.serverURL);
    this.bridge = adapters.bridge ?? new OpenCodeBridge(options.connectionFile);
    this.open = adapters.open ?? openBrowser;
    this.desktop = adapters.notify ?? notifyDesktop;
    this.queue = serial();
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
    this.credential = await readJSON(join4(this.options.stateDir, "credential.json"));
    if (!validCredential(this.credential) || this.credential.expiresAt <= Date.now())
      this.credential = null;
    this.state = await readJSON(join4(this.options.stateDir, "sync.json"), {});
    if (!this.credential) {
      await rm2(join4(this.options.stateDir, "credential.json"), { force: true });
      await rm2(join4(this.options.stateDir, "sync.json"), { force: true });
      const tokenPath = join4(this.options.stateDir, "access-token");
      if (await exists(tokenPath))
        await atomicWrite(tokenPath, "");
      await removeProvider(this.options.configPath);
      await clearMCP(this.options.stateDir);
      this.state = {};
    }
    if (this.authenticated())
      await this.refreshMCPCatalog().catch(() => {});
    this.configTimer = setInterval(() => this.backgroundRefresh(), this.options.refreshMs);
    this.loadTimer = setInterval(() => this.pollLoad().catch(() => {}), this.options.loadPollMs);
    this.configTimer.unref();
    this.loadTimer.unref();
    if (this.authenticated()) {
      this.backgroundRefresh();
      this.pollLoad().catch(() => {});
    }
  }
  authenticated() {
    return Boolean(this.credential && this.credential.expiresAt > Date.now());
  }
  token() {
    if (!this.authenticated())
      throw new Unauthorized;
    return this.credential.accessToken;
  }
  status() {
    return {
      authenticated: this.authenticated(),
      user: this.authenticated() ? this.credential.user : null,
      expiresAt: this.authenticated() ? this.credential.expiresAt : null,
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
    await atomicWrite(join4(this.options.stateDir, "sync.json"), JSON.stringify(this.state, null, 2));
  }
  async refresh() {
    if (this.refreshing)
      return this.refreshing;
    this.refreshing = this.queue(async () => {
      const token = this.token();
      try {
        const response = await this.api.request("/api/config", { token, etag: this.state.etag, signal: this.abort.signal });
        if (response.unchanged)
          this.state = { ...this.state, checkedAt: new Date().toISOString(), lastError: null };
        else {
          const applied = await applyConfig({ ...this.options, envelope: response.data, previous: this.state.revision ? this.state : null });
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
    this.credential = null;
    await Promise.all([rm2(join4(this.options.stateDir, "credential.json"), { force: true }), atomicWrite(join4(this.options.stateDir, "access-token"), "")]);
    await clearMCP(this.options.stateDir);
    this.mcpConfigs = [];
    await this.reloadMCP();
  }
  async reloadMCP() {
    await Promise.all([...this.mcpReloaders].map((reload) => reload()));
  }
  async refreshMCPCatalog() {
    const { data } = await this.api.request("/api/mcps", { token: this.token(), signal: this.abort.signal });
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
    const polledToken = this.credential?.accessToken;
    let next;
    try {
      const { data } = await this.api.request("/api/load", { token: this.token(), signal: this.abort.signal });
      if (!["green", "yellow", "red"].includes(data?.level) || typeof data.message !== "string" || data.message.length > 250 || !Number.isFinite(data.observedAt) || Math.abs(Date.now() - data.observedAt) > 90000)
        throw new Error("\u041D\u0435\u0442 \u0441\u0432\u0435\u0436\u0438\u0445 \u0434\u0430\u043D\u043D\u044B\u0445 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438");
      next = { level: data.level, message: data.message, queue: data.queue, checkedAt: data.observedAt };
    } catch (error) {
      next = { level: "unknown", message: error instanceof Unauthorized ? "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F /login" : "\u0421\u0435\u0440\u0432\u0435\u0440 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u0435\u043D", checkedAt: Date.now() };
      if (error instanceof Unauthorized)
        await this.queue(() => this.credential?.accessToken === polledToken ? this.invalidate() : undefined);
    } finally {
      this.polling = false;
    }
    if (this.abort.signal.aborted)
      return;
    if (this.credential && this.credential.accessToken !== polledToken)
      return;
    if (!this.credential && next.level !== "unknown")
      return;
    const changed = next.level !== this.load.level;
    this.load = next;
    if (changed)
      await this.notice(`${lights[next.level]} \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441: ${next.message}`, { green: "success", yellow: "warning", red: "error", unknown: "warning" }[next.level]);
  }
  track(promise, sessionID) {
    this.jobs.add(promise);
    promise.catch(async (error) => {
      if (!this.abort.signal.aborted) {
        await this.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043F\u043B\u0430\u0433\u0438\u043D", error.message).catch(() => {});
        await this.notice(error.message, "error");
      }
    }).finally(() => this.jobs.delete(promise));
  }
  async login(sessionID) {
    if (this.loginFlow || this.loginPending)
      throw new Error("\u0412\u0445\u043E\u0434 \u0443\u0436\u0435 \u043E\u0442\u043A\u0440\u044B\u0442 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435");
    this.loginPending = true;
    const generation = this.authGeneration;
    let flow;
    try {
      flow = await startLogin(this.api);
    } finally {
      this.loginPending = false;
    }
    if (generation !== this.authGeneration || this.abort.signal.aborted) {
      flow.cancel();
      return;
    }
    this.loginFlow = flow;
    const form = await this.bridge.form(sessionID, "\u0412\u0445\u043E\u0434 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode", [
      { type: "external", key: "login", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0443 \u0432\u0445\u043E\u0434\u0430", url: flow.url },
      { type: "string", key: "waiting", title: "\u0412\u0445\u043E\u0434 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode", description: `\u0412 \u043E\u0442\u043A\u0440\u044B\u0432\u0448\u0435\u043C\u0441\u044F \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435 \u0432\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0442\u0435\u0441\u0442\u043E\u0432\u0443\u044E \u0443\u0447\u0451\u0442\u043D\u0443\u044E \u0437\u0430\u043F\u0438\u0441\u044C. \u041F\u0430\u0440\u043E\u043B\u044C \u043D\u0435 \u043D\u0443\u0436\u0435\u043D. \u0415\u0441\u043B\u0438 \u0431\u0440\u0430\u0443\u0437\u0435\u0440 \u043D\u0435 \u043E\u0442\u043A\u0440\u044B\u043B\u0441\u044F, \u0441\u043A\u043E\u043F\u0438\u0440\u0443\u0439\u0442\u0435 \u0430\u0434\u0440\u0435\u0441: ${flow.url}`, custom: false, options: [{ value: "waiting", label: "\u041E\u0436\u0438\u0434\u0430\u044E \u0432\u0445\u043E\u0434\u0430 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435" }] }
    ]).catch((error) => {
      flow.cancel();
      this.loginFlow = null;
      throw error;
    });
    this.open(flow.url).catch(() => this.notice("\u041E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 \u0441\u0441\u044B\u043B\u043A\u0443 \u0432\u0445\u043E\u0434\u0430 \u0432 \u0444\u043E\u0440\u043C\u0435 OpenCode", "info"));
    const cancellation = new AbortController;
    this.bridge.wait(sessionID, form.id, AbortSignal.any([this.abort.signal, cancellation.signal])).then((answer) => {
      if (answer === null)
        flow.cancel();
    }).catch(() => {});
    this.track((async () => {
      try {
        const result = await flow.result;
        if (!validCredential(result) || result.expiresAt <= Date.now())
          throw new Error("\u0421\u0435\u0440\u0432\u0435\u0440 \u0432\u0435\u0440\u043D\u0443\u043B \u043D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u0443\u044E \u0430\u0432\u0442\u043E\u0440\u0438\u0437\u0430\u0446\u0438\u044E");
        validateConfig(result.configuration, this.options.serverURL);
        await this.queue(async () => {
          if (generation !== this.authGeneration || this.abort.signal.aborted)
            throw new Error("\u0412\u0445\u043E\u0434 \u043E\u0442\u043C\u0435\u043D\u0451\u043D");
          this.credential = { accessToken: result.accessToken, expiresAt: result.expiresAt, user: result.user };
          await clearMCP(this.options.stateDir);
          this.mcpConfigs = [];
          await this.reloadMCP();
          await atomicWrite(join4(this.options.stateDir, "credential.json"), JSON.stringify(this.credential));
          await atomicWrite(join4(this.options.stateDir, "access-token"), this.credential.accessToken);
          this.state = { ...await applyConfig({ ...this.options, envelope: result.configuration }), lastError: null };
          await this.persistState();
        });
        await this.bridge.message(sessionID, "\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", `${result.user.name}. \u041A\u043E\u043D\u0444\u0438\u0433 \u0432\u0435\u0440\u0441\u0438\u0438 ${this.state.revision} \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D. \u0414\u043E\u0441\u0442\u0443\u043F\u043D\u044B /refresh_config \u0438 /skills_load.`);
        await this.notice("\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D; \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433 \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D", "success");
        await this.pollLoad();
      } finally {
        cancellation.abort();
        await this.bridge.cancel(sessionID, form.id);
        this.loginFlow = null;
      }
    })(), sessionID);
  }
  async skills(sessionID, reload) {
    if (this.forms.has(sessionID))
      throw new Error("\u0424\u043E\u0440\u043C\u0430 \u0432\u044B\u0431\u043E\u0440\u0430 skills \u0443\u0436\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u0430");
    const token = this.token();
    const { data } = await this.api.request("/api/skills", { token, signal: this.abort.signal });
    const catalog = validateCatalog(data);
    if (!catalog.length)
      return this.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", "\u0414\u043B\u044F \u0432\u0430\u0448\u0435\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 skills.");
    const form = await this.bridge.form(sessionID, "\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", [{
      type: "multiselect",
      key: "skills",
      title: "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u043D\u0443\u0436\u043D\u044B\u0435 skills",
      description: "\u0417\u0430\u0433\u0440\u0443\u0437\u044F\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043E\u0442\u043C\u0435\u0447\u0435\u043D\u043D\u044B\u0435 skills. \u0423\u0436\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u044B\u0435 \u043E\u0441\u0442\u0430\u043D\u0443\u0442\u0441\u044F \u043D\u0430 \u043C\u0435\u0441\u0442\u0435.",
      custom: false,
      minItems: 0,
      default: [],
      options: catalog.map((skill) => ({ value: skill.id, label: `${skill.name} \xB7 ${skill.version}`, description: skill.description }))
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
          if (this.token() !== token)
            throw new Error("\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0430\u0441\u044C; \u043E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /skills_load \u0441\u043D\u043E\u0432\u0430");
          return installSkills({ ids: answer.skills ?? [], catalog, api: this.api, token, skillsDir: this.options.skillsDir, signal });
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
  async mcps(sessionID) {
    if (this.forms.has(sessionID))
      throw new Error("\u0424\u043E\u0440\u043C\u0430 \u0432\u044B\u0431\u043E\u0440\u0430 \u0443\u0436\u0435 \u043E\u0442\u043A\u0440\u044B\u0442\u0430");
    const token = this.token();
    const catalog = await this.refreshMCPCatalog();
    if (!catalog.length)
      return this.bridge.message(sessionID, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP", "\u0414\u043B\u044F \u0432\u0430\u0448\u0435\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438 \u043D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u044B\u0445 MCP.");
    const selected = this.mcpConfigs.map(({ name }) => name.slice(5));
    const form = await this.bridge.form(sessionID, "\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP", [{
      type: "multiselect",
      key: "mcps",
      title: "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 MCP",
      description: "\u041B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0432\u0432\u043E\u0434\u044F\u0442\u0441\u044F \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u043E \u0432 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u043C \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435, \u043D\u0435 \u0432 \u0447\u0430\u0442\u0435 OpenCode.",
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
        const tokens = new Map;
        for (const id of ids) {
          const item = catalog.find((entry) => entry.id === id);
          if (!item)
            throw new Error("\u0412\u044B\u0431\u0440\u0430\u043D MCP \u0432\u043D\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0433\u043E \u043A\u0430\u0442\u0430\u043B\u043E\u0433\u0430");
          if (selected.includes(id))
            continue;
          const page = await captureSecret(`\u041B\u0438\u0447\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D \u0434\u043B\u044F ${item.name}`);
          const cancel = () => page.cancel();
          signal.addEventListener("abort", cancel, { once: true });
          let notice;
          try {
            notice = await this.bridge.form(sessionID, `\u0422\u043E\u043A\u0435\u043D ${item.name}`, [{ type: "external", key: "token", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u0437\u0430\u0449\u0438\u0449\u0451\u043D\u043D\u0443\u044E \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u0443\u044E \u0444\u043E\u0440\u043C\u0443", url: page.url }]);
            await this.open(page.url).catch(() => {});
            tokens.set(id, await page.result);
          } finally {
            signal.removeEventListener("abort", cancel);
            page.cancel();
            if (notice)
              await this.bridge.cancel(sessionID, notice.id);
          }
        }
        await this.queue(async () => {
          if (this.token() !== token)
            throw new Error("\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0430\u0441\u044C; \u043E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 /mcps_load \u0441\u043D\u043E\u0432\u0430");
          this.mcpConfigs = await saveMCPSelection(this.options.stateDir, ids, catalog, tokens);
          await this.reloadMCP();
        });
        await this.bridge.message(sessionID, "MCP \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u044B", ids.length ? `${ids.map((id) => catalog.find((item) => item.id === id).name).join(`
`)}
\u041F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435 \u0447\u0435\u0440\u0435\u0437 /mcps.` : "\u0412\u0441\u0435 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u043E\u0442\u043A\u043B\u044E\u0447\u0435\u043D\u044B.");
      } finally {
        this.forms.delete(sessionID);
        await this.bridge.cancel(sessionID, form.id);
      }
    })(), sessionID);
  }
  async logout() {
    this.authGeneration++;
    this.loginFlow?.cancel();
    for (const { controller } of this.forms.values())
      controller.abort();
    await this.queue(async () => {
      const token = this.credential?.accessToken;
      await this.invalidate();
      this.state = {};
      await this.persistState();
      this.load = { level: "unknown", message: "\u0412\u0445\u043E\u0434 \u043D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", checkedAt: null };
      try {
        await removeProvider(this.options.configPath);
      } finally {
        if (token)
          await this.api.request("/oauth/revoke", { token, method: "POST", body: {} }).catch(() => {});
      }
    });
  }
  dispose() {
    clearInterval(this.configTimer);
    clearInterval(this.loadTimer);
    this.abort.abort();
    this.loginFlow?.cancel();
  }
}
function optionsFromEnv(env = process.env, settings = {}) {
  const profile = resolve(env.CORP_PROFILE_DIR ?? settings.profileDir ?? env.OPENCODE_CONFIG_DIR ?? join4(env.XDG_CONFIG_HOME ?? join4(homedir(), ".config"), "opencode"));
  const serviceFile = join4(env.XDG_STATE_HOME ?? join4(homedir(), ".local", "state"), "opencode", "service.json");
  const interval = (value, fallback) => {
    const n = Number(value ?? fallback);
    if (!Number.isFinite(n) || n < 50)
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0432\u0430\u043B \u043E\u043F\u0440\u043E\u0441\u0430");
    return n;
  };
  return {
    serverURL: trustedURL(env.CORP_SERVER_URL ?? settings.serverURL ?? "http://127.0.0.1:4310"),
    configPath: join4(profile, "opencode.jsonc"),
    stateDir: join4(profile, "corporate-state"),
    skillsDir: join4(profile, "skills"),
    connectionFile: env.CORP_OPENCODE_CONNECTION_FILE ?? settings.connectionFile ?? serviceFile,
    refreshMs: interval(env.CORP_REFRESH_INTERVAL_MS ?? settings.refreshMs, 3600000),
    loadPollMs: interval(env.CORP_LOAD_INTERVAL_MS ?? settings.loadPollMs, 30000)
  };
}

// src/plugin.js
var rpc = {
  id: "company.corporate",
  methods: { status: { input: { type: "object", properties: {}, additionalProperties: false }, output: { type: "object" } } },
  events: { notice: { schema: { type: "object", properties: { message: { type: "string" }, level: { type: "string" }, at: { type: "number" } }, required: ["message", "level", "at"] } } }
};
var registryKey = Symbol.for("company.opencode.corporate.runtime.v2");
var plugin_default = {
  id: "company-corporate",
  async setup(context) {
    const options = optionsFromEnv(process.env, context.options);
    const registry = globalThis[registryKey] ??= new Map;
    const key = `${options.configPath}|${options.serverURL}`;
    let entry = registry.get(key);
    if (!entry) {
      const runtime2 = new CorporateRuntime(options);
      entry = { runtime: runtime2, ready: runtime2.start(), refs: 0 };
      registry.set(key, entry);
    }
    entry.refs++;
    await entry.ready;
    const runtime = entry.runtime;
    const reloadMCP = () => context.mcp.reload();
    runtime.mcpReloaders.add(reloadMCP);
    const mcpRegistration = await context.mcp.transform((editor) => {
      for (const [name] of editor.list())
        if (name.startsWith("corp_"))
          editor.remove(name);
      if (runtime.authenticated())
        for (const { name, config } of runtime.mcpConfigs)
          editor.set(name, config);
    });
    const registration = await context.rpc.register(rpc, { status: async () => runtime.status() });
    const listener = (event) => registration.events.emit("notice", event);
    runtime.listeners.add(listener);
    const definitions = [
      ["login", "\u0412\u043E\u0439\u0442\u0438 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode \u0447\u0435\u0440\u0435\u0437 \u0431\u0440\u0430\u0443\u0437\u0435\u0440", (id) => runtime.login(id)],
      ["refresh_config", "\u041F\u043E\u043B\u0443\u0447\u0438\u0442\u044C \u0438 \u043F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433", async (id) => {
        const state = await runtime.refresh();
        await runtime.bridge.message(id, "\u041A\u043E\u043D\u0444\u0438\u0433 \u0430\u043A\u0442\u0443\u0430\u043B\u0435\u043D", `\u0412\u0435\u0440\u0441\u0438\u044F ${state.revision}. \u041F\u0440\u043E\u0432\u0435\u0440\u0435\u043D\u043E: ${state.checkedAt}`);
      }],
      ["skills_load", "\u0412\u044B\u0431\u0440\u0430\u0442\u044C \u0438 \u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", (id) => runtime.skills(id, () => context.skill.reload())],
      ["mcps_load", "\u0412\u044B\u0431\u0440\u0430\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 MCP \u0438 \u0432\u0432\u0435\u0441\u0442\u0438 \u043B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B", (id) => runtime.mcps(id)],
      ["logout", "\u0412\u044B\u0439\u0442\u0438 \u0438\u0437 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u043E\u0439 \u0443\u0447\u0451\u0442\u043D\u043E\u0439 \u0437\u0430\u043F\u0438\u0441\u0438", async (id) => {
        await runtime.logout();
        await runtime.bridge.message(id, "\u0412\u044B\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", "\u0422\u043E\u043A\u0435\u043D \u0443\u0434\u0430\u043B\u0451\u043D, \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440 \u043E\u0442\u043A\u043B\u044E\u0447\u0451\u043D. \u0421\u043A\u0430\u0447\u0430\u043D\u043D\u044B\u0435 skills \u0441\u043E\u0445\u0440\u0430\u043D\u0435\u043D\u044B.");
      }],
      ["corp_status", "\u0423\u0447\u0451\u0442\u043D\u0430\u044F \u0437\u0430\u043F\u0438\u0441\u044C, \u0432\u0435\u0440\u0441\u0438\u044F \u043A\u043E\u043D\u0444\u0438\u0433\u0430 \u0438 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441\u0430", async (id) => {
        const status = runtime.status();
        await runtime.bridge.message(id, "\u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u0441\u0442\u0430\u0442\u0443\u0441", `${status.authenticated ? status.user.name : "\u041D\u0435 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D \u0432\u0445\u043E\u0434 \u2014 /login"}
\u041A\u043E\u043D\u0444\u0438\u0433: ${status.config.revision ?? "\u043D\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043D"}
\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u044F\u044F \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0430: ${status.config.checkedAt ?? "\u0435\u0449\u0451 \u043D\u0435 \u0431\u044B\u043B\u043E"}
${lights[status.load.level]} ${status.load.message}
\u0410\u0432\u0442\u043E\u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435: ${status.refreshMinutes} \u043C\u0438\u043D.${status.config.lastError ? `
${status.config.lastError}` : ""}`);
      }],
      ["inference_status", "\u0421\u0432\u0435\u0442\u043E\u0444\u043E\u0440 \u043D\u0430\u0433\u0440\u0443\u0437\u043A\u0438 \u043D\u0430 \u0438\u043D\u0444\u0435\u0440\u0435\u043D\u0441", async (id) => {
        runtime.token();
        await runtime.pollLoad();
        await runtime.bridge.message(id, `${lights[runtime.load.level]} \u0418\u043D\u0444\u0435\u0440\u0435\u043D\u0441`, runtime.load.message);
      }]
    ];
    await context.command.transform((commands) => {
      for (const [name, description, execute] of definitions)
        commands.add({ name, description, async execute({ sessionID }) {
          try {
            if (name !== "login" && !runtime.authenticated()) {
              await runtime.bridge.message(sessionID, `/${name}`, "\u0421\u043D\u0430\u0447\u0430\u043B\u0430 \u0432\u044B\u043F\u043E\u043B\u043D\u0438\u0442\u0435 /login, \u0447\u0442\u043E\u0431\u044B \u0432\u043E\u0439\u0442\u0438 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 OpenCode.");
              return;
            }
            await execute(sessionID);
          } catch (error) {
            await runtime.bridge.message(sessionID, `/${name}`, error.message);
          }
        } });
    });
    return () => {
      runtime.mcpReloaders.delete(reloadMCP);
      mcpRegistration.dispose?.();
      runtime.listeners.delete(listener);
      if (--entry.refs === 0) {
        runtime.dispose();
        registry.delete(key);
      }
    };
  }
};
export {
  plugin_default as default
};
