const ALLOWED_METHODS = {

  gmailApp: [
    "GmailApp.getInboxThreads",
    "GmailApp.getInboxUnreadCount",
    "GmailApp.getSpamThreads",
    "GmailApp.getSpamUnreadCount",
    "GmailApp.getPriorityInboxThreads",
    "GmailApp.getPriorityInboxUnreadCount",
    "GmailApp.search",
    "GmailApp.getThreadById",
    "GmailApp.getMessageById",
    "GmailApp.getUserLabelByName",
  ],
  
  instance: [
    "getMessages",        //thread
    "getSubject",         //message
    "getBody",            //message
    "getPlainBody",       //message
    "getFrom",            //message
    "getTo",              //message
    "getDate",            //message
    "getAttachments",     //message
    "getMessageCount",    //thread
    "isUnread",           //message
    "getId",              //message
    "getHeader",          //message
    "getLabels",          //message
    "getLastMessageDate", //thread
    "isImportant",        //thread
    "isInSpam",           //thread
  ],
  
  generic: [
    "Logger.log",
    "console.log",
    "JSON.parse",
    "JSON.stringify"
  ],

  array:[
    "map",
    "forEach",
    "filter",
    "length",
    "reduce",
    "slice",
  ],

  date: [
    "new Date",          //new Date()
    "Date.now",          //Date.now()
    "getDate",           //date.getDate()
    "getDay",            //date.getDay()
    "getFullYear",       //date.getFullYear()
    "getHours",          //date.getHours()
    "getMilliseconds",   //date.getMilliseconds()
    "getMinutes",        //date.getMinutes()
    "getMonth",          //date.getMonth()
    "getSeconds",        //date.getSeconds()
    "getTime",           //date.getTime()
    "getTimezoneOffset", //date.getTimezoneOffset()
    "getUTCDate",        //date.getUTCDate()
    "setHours",          //date.setHours()
    "toISOString",       //date.toISOString()
    "toJSON"             //date.toJSON()
  ],

  string: [
    "split",
    "substring",
    "slice",
    "length"
  ],

  loops: [
    "for",
  ]
};


//for reference:
// \w+                            : 1 or more character
// \s*                            : 0 or more whitespace
// \b                             : word boundary, transition from word to non word char
// \.                             : exact match for dot
// \[                             : finding square bracket [ 
// /\w+\[['"`]\w+['"`]\]/         : chars[(any quotes) chars (any quotes)]
// (...)                          : match in group


const BLACKLISTED_PATTERNS = [
  
  /*/\.(sendEmail|reply|forward|moveToTrash|markRead|markUnread|star|unstar)\(/,*/
  /\.(sendEmail|reply|forward|moveToTrash)\(/,
  /\.(setLabel|addLabel|removeLabel|deleteLabel)\(/,
  /(UrlFetchApp|XMLHttpRequest|new Function|eval\()/,
  /(mailto:|window\.open|fetch\()/,

  /\w+\[['"`]\w+['"`]\]/,                    // e.g., Logger['log']
  /\[['"`](constructor|__proto__|prototype)['"`]\]/, // prototype access
  /Object\.getPrototypeOf.*constructor/,     // async function(){} constructor pattern
  /constructor\s*\.\s*constructor/,          // obj.constructor.constructor(...)
  /Function\(["'`][^"'`]*["'`]\)/,           // direct Function call
  /Function\(`[^`]*`\)/,                     // template-literal Function

  /return\s+this/,                           // Function("return this")
  /globalThis/,                              // global object
  /window/,                                  // browser global
  /this\s*\.\s*constructor/,                 // this.constructor

  /\.\s*\[[^\]]+\]\s*\(/,          // e.g. obj['method']()
  /\.constructor\s*\(/,             // Constructor access
  /Function\s*\.\s*prototype/,     // Function prototype
  /(toString|valueOf)\s*\(/,        // Implicit conversion
  /new\s+Function\s*\(/,            // Alternate Function constructor
  /\bimport\b/,                     // import
  /\brequire\b/,                    // require
  /`\s*\+\s*`/,                     // Template literal concatenation
  /\$\{[^}]+\}/,                     // Template literal expressions

  /GmailApp\s*\[[^\]]+\]/,          // GmailApp['method'](yyy)
  /\w+\s*\[\s*\w+\s*\]\s*\(/,       // obj['method']()
  /\.\s*\[[^\]]+\]\s*\(/,            // obj.['prop']['method']()
  /\b(?:sendEmail|reply|forward)\b/,  // Direct method name match
  /(['"`]\s*\+\s*['"`])/,            // String concat
];

function detectBracketAccess(code) {
  const patterns = [
    /\[\s*["'`](\w+)["'`]\s*\]/g,   // obj['property']
    /\[\s*(\w+)\s*\]/g,             // obj[property]
    /\.\s*\[/g,                     // obj.['property'] ?
  ];

  const disallowedProps = [
    'constructor', '__proto__', 'prototype', 
    'log', 'apply', 'call', 'bind', 'eval'
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(code)) !== null) {
      const prop = match[1] || '';
      if (disallowedProps.some(p => prop.includes(p))) {
        throw new Error(`Blocked: Indirect property access via [${prop}]`);
      }
    }
  }
  return true;
}


function extractMethodCalls(code) {
  const methodPattern = /\b([\w$]+)(?:\.(\w+))?\s*\(/g;
  const methods = new Set();
  let match;

  while ((match = methodPattern.exec(code)) !== null) {
    const objectOrFunc = match[1];
    const method = match[2];

    if (!method) {
      methods.add(objectOrFunc); // global function call like askGemini()
    } else {
      methods.add(`${objectOrFunc}.${method}`);
    }
  }
  return Array.from(methods);
}

function isAllowedMethod(method) {
  const [obj, fn] = method.split(".");

  if (!fn) {
    return true; // simple function call like askGemini()
  }

  //Google APIs (only Gmail for now)
  if (obj === "GmailApp") {
    return ALLOWED_METHODS.gmailApp.includes(method);
  }

  if (ALLOWED_METHODS.instance.includes(fn)) return true;
  if (ALLOWED_METHODS.generic.includes(method)) return true;
  if (ALLOWED_METHODS.array.includes(fn)) return true;
  if (ALLOWED_METHODS.date.includes(fn)) return true;
  if (ALLOWED_METHODS.string.includes(fn)) return true;

  return false;
}

function validateCode(code) {
  const methods = extractMethodCalls(code);

  for (const m of methods) {
    if (!isAllowedMethod(m)) {
      throw new Error(`Blocked: ${m} is not an allowed method.`);
    }
  }

  for (const pattern of BLACKLISTED_PATTERNS) {
    if (pattern.test(code)) {
      throw new Error(`Blocked: matches blacklisted pattern: ${pattern}`);
    }
  }

  // Check bracket access
  detectBracketAccess(code);

  return true;
}



function createSafeEnvironment() {
  const frozenEmpty = Object.freeze({});   //prevent adding/changing of methods
  const frozenArray = Object.freeze([]);

  // Helper to wrap methods with optional argument validation
  const wrap = (obj, methodName, argValidator = () => true) => {
    return function (...args) {
      if (!argValidator(args)) {
        throw new Error(`Invalid arguments to ${methodName}`);
      }
      return obj[methodName].apply(obj, args);
    };
  };

  const frozenFetch = Object.freeze({
    fetch: (url, options) => {
      if (!url.includes('generativelanguage.googleapis.com')) {
        throw new Error('Only Gemini API calls are allowed');
      }
      return UrlFetchApp.fetch(url, options);
    }
  });

  const safeGmail = {
    getInboxThreads: wrap(GmailApp, 'getInboxThreads', (args) => args.length <= 2),
    search: wrap(GmailApp, 'search', (args) => args.length === 1 && typeof args[0] === 'string'),
    getThreadById: wrap(GmailApp, 'getThreadById', (args) => args.length === 1 && typeof args[0] === 'string'),
    getMessageById: wrap(GmailApp, 'getMessageById', (args) => args.length === 1 && typeof args[0] === 'string'),
    getUserLabelByName: wrap(GmailApp, 'getUserLabelByName', (args) => args.length === 1 && typeof args[0] === 'string'),
  };

  const threadWrapper = (thread) => Object.freeze({
    getMessages: wrap(thread, 'getMessages', (args) => args.length === 0),
    getMessageCount: wrap(thread, 'getMessageCount', (args) => args.length === 0),
    
    getLastMessageDate: wrap(thread, 'getLastMessageDate', (args) => args.length === 0),
    isImportant: wrap(thread, 'isImportant', (args) => args.length === 0),
    isInSpam: wrap(thread, 'isInSpam', (args) => args.length === 0),
    
    getId: wrap(thread, 'getId', (args) => args.length === 0),
    getLabels: wrap(thread, 'getLabels', (args) => args.length === 0)
  });

  const messageWrapper = (message) => Object.freeze({
    getSubject: wrap(message, 'getSubject', (args) => args.length === 0),
    getBody: wrap(message, 'getBody', (args) => args.length === 0),
    getPlainBody: wrap(message, 'getPlainBody', (args) => args.length === 0),
    
    getFrom: wrap(message, 'getFrom', (args) => args.length === 0),
    getTo: wrap(message, 'getTo', (args) => args.length === 0),
    getHeader: wrap(message, 'getHeader', (args) => 
      args.length === 1 && typeof args[0] === 'string'),
    
    getDate: wrap(message, 'getDate', (args) => args.length === 0),
    isUnread: wrap(message, 'isUnread', (args) => args.length === 0),
    getId: wrap(message, 'getId', (args) => args.length === 0),
    
    getAttachments: wrap(message, 'getAttachments', (args) => args.length === 0),
    
    getLabels: wrap(message, 'getLabels', (args) => args.length === 0)
  });

  const safeArrayMethods = {
    map: wrap(Array.prototype, 'map'),
    forEach: wrap(Array.prototype, 'forEach'),
    filter: wrap(Array.prototype, 'filter'),
    reduce: wrap(Array.prototype, 'reduce', (args) => args.length <= 2)
  };

  const wrapArray = (arr) => {
    const wrapper = Object.create(safeArrayMethods);
    wrapper.length = arr.length;
    for (let i = 0; i < arr.length; i++) {
      const el = arr[i];
      if (el?.getMessages) {
        wrapper[i] = threadWrapper(el);
      } else if (el?.getSubject) {
        wrapper[i] = messageWrapper(el);
      } else {
        wrapper[i] = el;
      }
    }
    return Object.freeze(wrapper);
  };

  function SafeDate(...args) {
    return new Date(...args);
  }
  SafeDate.now = Date.now;
  SafeDate.parse = Date.parse;
  SafeDate.prototype = Date.prototype;

  return Object.freeze({
    GmailApp: Object.freeze(safeGmail),
    console: Object.freeze({
      log: (...args) => console.log(...args.map((x) => typeof x === 'object' ? JSON.stringify(x) : x))
    }),
    JSON: Object.freeze({ parse: JSON.parse, stringify: JSON.stringify }),
    Date: Object.freeze(SafeDate),
    Utilities: typeof Utilities !== 'undefined'
      ? Object.freeze({
          formatDate: wrap(Utilities, 'formatDate', (args) => args.length === 3)
        })
      : {},

    askGemini: (prompt) => {
      if (typeof prompt !== 'string' || prompt.length > 10000) {
        throw new Error('Invalid prompt');
      }

      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${SECRET_KEY}`;
      const payload = {
        contents: [{ parts: [{ text: prompt }] }]
      };

      const options = {
        contentType: "application/json",
        muteHttpExceptions: true,
        payload: JSON.stringify(payload)
      };

      const response = frozenFetch.fetch(url, options);
      return JSON.parse(response.getContentText());
    },

    _wrapArray: wrapArray,
    _wrapDate: (d) => Object.freeze(new Date(d.getTime()))
  });
}


/**
 * Safely executes Gemini-generated code after validation
 * @param {string} geminiResponse - Raw response from Gemini API
 * @returns {Object} {success: boolean, result: any, error: string}
 */
function safeExecute(geminiResponse) {

  let code = extractCodeFromGemini(geminiResponse);
  if (!code) return { success: false, error: "No valid code block" };

  try {
    validateCode(code);

    const env = createSafeEnvironment();

    const wrappedCode = `
      "use strict";
      return (function() {
        let result;
        try {
          ${code}
          return { success: true, result: typeof result !== 'undefined' ? result : null };
        } catch (e) {
          return { success: false, error: e.message };
        }
      })();
    `;

    const func = new Function(
      'GmailApp', 'console', 'JSON', 'Date', 'Utilities',
      wrappedCode
    );

    const result = func.call(
      env,
      env.GmailApp,
      env.console,
      env.JSON,
      env.Date,
      env.Utilities
    );

    return result;

  } catch (e) {
    return { 
      success: false, 
      error: `Execution failed: ${e.message}`,
      details: e.stack 
    };
  }
}

/**
 * Executes Gemini-generated code !!WITHOUT VALIDATION!!
 * @param {string} geminiResponse - Raw response from Gemini API
 * @returns {Object} {success: boolean, result: any, error: string}
 */
function executeWithoutValidation(geminiResponse) {
  let code = extractCodeFromGemini(geminiResponse);
  if (!code) return { success: false, error: "No valid code block" };

  try {

    const env = createSafeEnvironment();

    const wrappedCode = `
      "use strict";
      return (function() {
        let result;
        try {
          ${code}
          return { success: true, result: typeof result !== 'undefined' ? result : null };
        } catch (e) {
          return { success: false, error: e.message };
        }
      })();
    `;

    const func = new Function(
      'GmailApp', 'console', 'JSON', 'Date', 'Utilities',
      wrappedCode
    );

    const result = func.call(
      env,
      env.GmailApp,
      env.console,
      env.JSON,
      env.Date,
      env.Utilities
    );

    return result;
    
  } catch (e) {
    return { 
      success: false, 
      error: `Execution failed: ${e.message}`,
      details: e.stack 
    };
  }
}


/** Extracts code from ```javascript ``` blocks
* @params {String} response - Gemini's response of form ```javascript code```
*/
function extractCodeFromGemini(response) {
  const match = response.match(/```javascript([\s\S]*?)```/);
  return match ? match[1].trim() : null;
}


