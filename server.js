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
  const provider = client === "kilo" ? { name: source.name, npm: "@ai-sdk/openai-compatible", options: { baseURL: source.settings.baseURL, apiKey: `{file:${join2(stateDir, "access-token")}}` }, models: source.models } : { ...source, package: "@ai-sdk/openai-compatible", settings: { ...source.settings, apiKey: `{file:${join2(stateDir, "access-token")}}` } };
  const field = client === "kilo" ? "provider" : "providers";
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

// src/secret-page.js
import { createServer } from "http";
var maxToken = 512;
function page(items, action, csrf) {
  const fields = items.map((item, index) => `<section class="system"><div class="system-head"><span class="number">${String(index + 1).padStart(2, "0")}</span><div><h2>${escapeHTML(item.name)}</h2><p>${escapeHTML(item.description)}</p></div></div><label for="token-${index}">\u041B\u0438\u0447\u043D\u044B\u0439 \u0442\u043E\u043A\u0435\u043D</label><input id="token-${index}" name="token:${escapeHTML(item.id)}" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="${maxToken}" placeholder="\u0412\u0441\u0442\u0430\u0432\u044C\u0442\u0435 \u0442\u043E\u043A\u0435\u043D \u0434\u043B\u044F ${escapeHTML(item.name)}" required></section>`).join("");
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0435 MCP</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 90% 0%,#d7ebe8 0,transparent 38%),#f3f6f7}main{width:min(720px,calc(100% - 32px));margin:56px auto 72px}.brand{display:flex;align-items:center;gap:12px;color:#264e54;font-size:13px;font-weight:750;letter-spacing:.11em;text-transform:uppercase}.mark{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#15766d;color:white;font-size:21px;font-weight:700;letter-spacing:0}.panel{margin-top:22px;padding:clamp(24px,5vw,44px);background:#fff;border:1px solid #e0e8e9;border-radius:24px;box-shadow:0 20px 60px #1c434b12}h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.15;letter-spacing:-.035em}.lead{margin:15px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}.notice{display:flex;gap:12px;margin:26px 0 8px;padding:15px 17px;background:#ecf8f5;border:1px solid #cce8e1;border-radius:13px;color:#275f57;font-size:14px;line-height:1.45}.notice b{font-size:18px;line-height:1}.system{padding:25px 0;border-bottom:1px solid #e9eef0}.system-head{display:flex;gap:16px;align-items:flex-start}.number{display:grid;place-items:center;flex:none;width:35px;height:35px;border-radius:10px;background:#eaf1f2;color:#4b7278;font-size:12px;font-weight:750}.system h2{margin:1px 0 5px;font-size:19px;letter-spacing:-.015em}.system p{margin:0;color:#64747e;font-size:14px;line-height:1.45}.system label{display:block;margin:20px 0 8px;color:#344a54;font-size:13px;font-weight:700}.system input{display:block;width:100%;height:48px;padding:0 14px;border:1px solid #bdcdd1;border-radius:10px;background:#fbfdfd;color:#17212b;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}.system input:focus{border-color:#15766d;box-shadow:0 0 0 4px #15766d20}.system input::placeholder{color:#9ba9ae}.footer{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:28px}.footnote{max-width:350px;color:#667780;font-size:13px;line-height:1.45}button{border:0;border-radius:11px;padding:14px 23px;background:#126d64;color:#fff;font:inherit;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 6px 16px #126d642d}button:hover{background:#0d5a52}button:focus-visible{outline:3px solid #71cabe;outline-offset:3px}@media(max-width:600px){main{margin:24px auto 40px}.panel{border-radius:18px}.footer{align-items:stretch;flex-direction:column-reverse}button{width:100%}}
  </style></head><body><main><div class="brand"><span class="mark">\u2197</span> \u041A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\u044B</div><div class="panel"><h1>\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u0435 \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0435 \u0441\u0438\u0441\u0442\u0435\u043C\u044B</h1><p class="lead">\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0434\u043B\u044F ${items.length} ${items.length % 10 === 1 && items.length % 100 !== 11 ? "\u0441\u0438\u0441\u0442\u0435\u043C\u044B" : "\u0441\u0438\u0441\u0442\u0435\u043C"}. \u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442 MCP \u0432 \u0442\u0435\u043A\u0443\u0449\u0435\u043C \u0437\u0430\u043F\u0443\u0441\u043A\u0435 OpenCode \u0438\u043B\u0438 Kilo.</p><div class="notice"><b>\u25C8</b><span>\u0422\u043E\u043A\u0435\u043D\u044B \u043F\u0435\u0440\u0435\u0434\u0430\u044E\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u043C\u0443 \u043F\u043B\u0430\u0433\u0438\u043D\u0443. \u041E\u043D\u0438 \u043D\u0435 \u043F\u043E\u044F\u0432\u044F\u0442\u0441\u044F \u0432 \u0447\u0430\u0442\u0435 \u0438 \u043D\u0435 \u0431\u0443\u0434\u0443\u0442 \u0437\u0430\u043F\u0438\u0441\u0430\u043D\u044B \u0432 \u0444\u0430\u0439\u043B \u043A\u043E\u043D\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438.</span></div><form method="post" action="${action}" autocomplete="off"><input type="hidden" name="csrf" value="${csrf}">${fields}<div class="footer"><span class="footnote">\u041F\u043E\u0441\u043B\u0435 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u043A\u0430 \u043F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u044F \u043F\u043E\u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0432\u0432\u0435\u0441\u0442\u0438 \u0442\u043E\u043A\u0435\u043D\u044B \u0441\u043D\u043E\u0432\u0430.</span><button type="submit">\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C ${items.length} MCP</button></div></form></div></main></body></html>`;
}
async function captureSecrets(items, { timeoutMs = 300000 } = {}) {
  if (!Array.isArray(items) || !items.length || items.length > 30 || new Set(items.map((item) => item.id)).size !== items.length || items.some((item) => !/^[a-z][a-z0-9_-]{0,39}$/.test(item.id)))
    throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0441\u043F\u0438\u0441\u043E\u043A MCP \u0434\u043B\u044F \u0432\u0432\u043E\u0434\u0430 \u0442\u043E\u043A\u0435\u043D\u043E\u0432");
  const nonce = random();
  const csrf = random();
  let settled = false;
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
    const tokens = new Map(items.map((item) => [item.id, form.get(`token:${item.id}`)]));
    response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<!doctype html><html lang=ru><meta charset=utf-8><title>MCP \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0430\u044E\u0442\u0441\u044F</title><style>body{font:16px system-ui;max-width:32rem;margin:12vh auto;padding:2rem;background:#f3f6f7;color:#17212b}main{padding:2rem;background:white;border-radius:18px}h1{font-size:25px}</style><main><h1>\u0422\u043E\u043A\u0435\u043D\u044B \u043F\u0435\u0440\u0435\u0434\u0430\u043D\u044B</h1><p>\u041F\u043B\u0430\u0433\u0438\u043D \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0435 MCP. \u042D\u0442\u0443 \u0432\u043A\u043B\u0430\u0434\u043A\u0443 \u043C\u043E\u0436\u043D\u043E \u0437\u0430\u043A\u0440\u044B\u0442\u044C.</p></main></html>");
    if (!settled) {
      settled = true;
      accept(tokens);
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
var validCredential = (value) => value && typeof value.accessToken === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value.accessToken) && Number.isFinite(value.expiresAt) && typeof value.user?.name === "string";

class CorporateRuntime {
  constructor(options, adapters = {}) {
    this.options = options;
    this.api = adapters.api ?? new CorporateAPI(options.serverURL);
    this.bridge = adapters.bridge ?? new OpenCodeBridge(options.connectionFile);
    this.applyConfig = adapters.applyConfig ?? applyConfig;
    this.removeProvider = adapters.removeProvider ?? removeProvider;
    this.syncMCP = adapters.syncMCP;
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
    await Promise.all([
      rm2(join4(this.options.stateDir, "mcp-selection.json"), { force: true }),
      rm2(join4(this.options.stateDir, "mcp-tokens"), { force: true, recursive: true })
    ]);
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
      await this.removeProvider(this.options.configPath, this.options.client);
      await clearMCP(this.options.stateDir);
      await this.syncMCP?.([]);
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
          const applied = await this.applyConfig({ ...this.options, envelope: response.data, previous: this.state.revision ? this.state : null });
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
    await this.syncMCP?.(this.mcpConfigs);
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
    const form = sessionID ? await this.bridge.form(sessionID, `\u0412\u0445\u043E\u0434 \u0432 \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 ${clientName}`, [
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
          this.state = { ...await this.applyConfig({ ...this.options, envelope: result.configuration }), lastError: null };
          await this.persistState();
        });
        await reload();
        if (form)
          await this.bridge.message(sessionID, "\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D", `${result.user.name}. \u041A\u043E\u043D\u0444\u0438\u0433 \u0432\u0435\u0440\u0441\u0438\u0438 ${this.state.revision} \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D. \u0414\u043E\u0441\u0442\u0443\u043F\u043D\u044B /refresh_config \u0438 /skills_load.`);
        await this.notice("\u0412\u0445\u043E\u0434 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D; \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0439 \u043A\u043E\u043D\u0444\u0438\u0433 \u043F\u0440\u0438\u043C\u0435\u043D\u0451\u043D", "success");
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
  async mcps(sessionID, reload = async () => {}) {
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
      description: `\u041B\u0438\u0447\u043D\u044B\u0435 \u0442\u043E\u043A\u0435\u043D\u044B \u0432\u0432\u043E\u0434\u044F\u0442\u0441\u044F \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u043E \u0432 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u043C \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435, \u043D\u0435 \u0432 \u0447\u0430\u0442\u0435 ${this.options.client === "kilo" ? "Kilo" : "OpenCode"}.`,
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
        }).filter((item) => !selected.includes(item.id));
        let tokens = new Map;
        if (requested.length) {
          const page2 = await captureSecrets(requested);
          const cancel = () => page2.cancel();
          signal.addEventListener("abort", cancel, { once: true });
          let notice;
          try {
            notice = await this.bridge.form(sessionID, "\u0422\u043E\u043A\u0435\u043D\u044B \u0432\u044B\u0431\u0440\u0430\u043D\u043D\u044B\u0445 MCP", [{ type: "external", key: "tokens", title: "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u0443\u044E \u0444\u043E\u0440\u043C\u0443 \u0434\u043B\u044F \u0442\u043E\u043A\u0435\u043D\u043E\u0432", url: page2.url }]);
            await this.open(page2.url).catch(() => {});
            tokens = await page2.result;
          } finally {
            signal.removeEventListener("abort", cancel);
            page2.cancel();
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
        await reload();
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
        await this.removeProvider(this.options.configPath, this.options.client);
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
    clearMCPEnv(this.options.stateDir);
  }
}
function optionsFromEnv(env = process.env, settings = {}) {
  const client = settings.client === "kilo" ? "kilo" : "opencode";
  const profile = resolve((client === "kilo" ? env.CORP_KILO_PROFILE_DIR : undefined) ?? env.CORP_PROFILE_DIR ?? settings.profileDir ?? (client === "kilo" ? env.KILO_CONFIG_DIR : env.OPENCODE_CONFIG_DIR) ?? join4(env.XDG_CONFIG_HOME ?? join4(homedir(), ".config"), client));
  const serviceFile = join4(env.XDG_STATE_HOME ?? join4(homedir(), ".local", "state"), "opencode", "service.json");
  const interval = (value, fallback) => {
    const n = Number(value ?? fallback);
    if (!Number.isFinite(n) || n < 50)
      throw new Error("\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0432\u0430\u043B \u043E\u043F\u0440\u043E\u0441\u0430");
    return n;
  };
  return {
    client,
    serverURL: trustedURL(env.CORP_SERVER_URL ?? settings.serverURL ?? "http://127.0.0.1:4310"),
    configPath: join4(profile, client === "kilo" ? "kilo.jsonc" : "opencode.jsonc"),
    stateDir: join4(profile, "corporate-state"),
    skillsDir: join4(profile, "skills"),
    connectionFile: env.CORP_OPENCODE_CONNECTION_FILE ?? settings.connectionFile ?? serviceFile,
    refreshMs: interval(env.CORP_REFRESH_INTERVAL_MS ?? settings.refreshMs, 3600000),
    loadPollMs: interval(env.CORP_LOAD_INTERVAL_MS ?? settings.loadPollMs, 30000)
  };
}

// src/kilo-control.js
import { createServer as createServer3 } from "http";
import { timingSafeEqual as timingSafeEqual2 } from "crypto";
import { rmSync } from "fs";
import { join as join5 } from "path";

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
  { name: "skills_load", description: "\u0412\u044B\u0431\u0440\u0430\u0442\u044C \u0438 \u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", kiloDescription: "\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u043A\u043E\u0440\u043F\u043E\u0440\u0430\u0442\u0438\u0432\u043D\u044B\u0435 skills", reload: true },
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
      runtime.token();
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
          if (name !== "login" && !runtime.authenticated()) {
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
var key = Symbol.for("company.kilo.corporate.control.v3");
var legacyKeys = [Symbol.for("company.kilo.corporate.control.v2"), Symbol.for("company.kilo.corporate.control.v1")];
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
    syncMCP: (configs) => syncKiloMCP(options.configPath, options.stateDir, configs)
  });
  await runtime.start();
  const secret = random();
  const queue = serial();
  const execute = (command) => queue(async () => {
    messages = [];
    if (command !== "login" && !runtime.authenticated())
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
    const ownFile = join5(options.stateDir, `control-${process.pid}.json`);
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
    await atomicWrite(join5(options.stateDir, "control.json"), state);
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
import { readFile as readFile4 } from "fs/promises";
import { dirname as dirname2, join as join6 } from "path";
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
  const script = join6(options.stateDir, "workflow-command.mjs");
  await atomicWrite(script, helper);
  const conflicts = [];
  for (const { name, kiloDescription: description } of commands) {
    const file = join6(dirname2(options.configPath), "commands", `${name}.md`);
    const current = await exists(file);
    if (current) {
      if (current.isSymbolicLink()) {
        conflicts.push(name);
        continue;
      }
      const content2 = await readFile4(file, "utf8");
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
var registryKey = Symbol.for("company.opencode.corporate.runtime.v6");
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
