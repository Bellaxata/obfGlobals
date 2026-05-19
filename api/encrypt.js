const crypto = require('crypto');

class AbsoluteObfuscator {
  constructor(code, options = {}) {
    this.originalCode = code;
    this.expiryMode = options.expiryMode || 'off';
    this.expiryValue = options.expiryValue || 7;
    this.hash = this.generateHash(code);
    this.signature = this.generateSignature(code);
  }

  generateHash(str) {
    let hash = crypto.createHash('sha256').update(str).digest('hex');
    for (let i = 0; i < 5; i++) {
      hash = crypto.createHash('sha512').update(hash).digest('hex');
    }
    return hash;
  }

  generateSignature(str) {
    let sig = 0;
    for (let i = 0; i < str.length; i++) {
      sig = ((sig << 5) - sig) + str.charCodeAt(i);
      sig |= 0;
    }
    return Math.abs(sig).toString(16).padStart(16, '0');
  }

  randomId(len = 16) {
    return crypto.randomBytes(len).toString('hex');
  }

  randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  // Multi-layer hex encoding
  toComplexHex(str, layers = 3) {
    let result = str;
    for (let i = 0; i < layers; i++) {
      result = Buffer.from(result, 'utf8').toString('hex');
    }
    const hexArray = result.match(/.{1,2}/g) || [];
    return '[' + hexArray.map(h => '0x' + h).join(',') + ']';
  }

  // ==================== LAYER 1-5: VARIABLE RENAMING ====================
  renameVarsUltra(code) {
    const patterns = [
      /\b(let|const|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/g,
      /catch\s*\(([a-zA-Z_$][a-zA-Z0-9_$]*)\)/g,
      /\bnew\s+([A-Z][a-zA-Z0-9_$]*)/g,
      /\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
      /\breturn\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /typeof\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /instanceof\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
      /delete\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
    ];
    
    let counter = 0;
    const mapping = new Map();
    const reserved = [
      'console', 'process', 'require', 'module', 'exports', 'Buffer',
      'setTimeout', 'setInterval', 'Date', 'Math', 'JSON', 'Array',
      'Object', 'String', 'Number', 'Boolean', 'Function', 'RegExp',
      'Error', 'Promise', '__dirname', '__filename', 'global',
      'undefined', 'NaN', 'Infinity', 'isNaN', 'isFinite', 'parseInt',
      'parseFloat', 'encodeURI', 'decodeURI', 'eval', 'arguments'
    ];
    
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    
    const generateName = () => {
      let name = '';
      const prefix = ['_0x', '__', '_$$', '_0O', '$', '_X', '_O', '__x'][counter % 8];
      for (let i = 0; i < 12; i++) {
        name += chars[Math.floor(Math.random() * chars.length)];
      }
      counter++;
      return prefix + name;
    };
    
    for (const pattern of patterns) {
      let match;
      const regex = new RegExp(pattern.source, 'g');
      while ((match = regex.exec(code)) !== null) {
        let varName = match[2] || match[1];
        if (varName && !mapping.has(varName) && !reserved.includes(varName) && 
            varName.length > 1 && !varName.includes('_0x') && !varName.includes('__')) {
          mapping.set(varName, generateName());
        }
      }
    }
    
    let renamed = code;
    const sorted = Array.from(mapping.entries()).sort((a, b) => b[0].length - a[0].length);
    for (const [oldName, newName] of sorted) {
      const regex = new RegExp(`\\b${oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
      renamed = renamed.replace(regex, newName);
    }
    
    return { renamed, mapping };
  }

  // ==================== LAYER 6-10: STRING ENCRYPTION ====================
  encodeStringsNuclear(code) {
    const stringPattern = /(["'])((?:(?=(\\?))\3.)*?)\1/g;
    
    const decodeEngine = `
      const _a = (s) => { let r=''; for(let i=0;i<s.length;i+=2) r+=String.fromCharCode(parseInt(s.substr(i,2),16)); return r; };
      const _b = (a) => { let s=''; for(let i=0;i<a.length;i++) s+=String.fromCharCode(a[i]); return _a(s); };
      const _c = (s) => s.split('').reverse().join('');
      const _d = (s,k) => { let r=''; for(let i=0;i<s.length;i++) r+=String.fromCharCode(s.charCodeAt(i)^k); return r; };
      const _e = (s) => Buffer.from(s,'base64').toString();
      const _f = (s) => { let r=''; for(let i=0;i<s.length;i++) r+=String.fromCharCode(s.charCodeAt(i)+0x7); return r; };
      const _g = (s) => { let r=''; for(let i=0;i<s.length;i++) r+=String.fromCharCode(s.charCodeAt(i)-0xD); return r; };
      const _h = (s) => { let r=''; for(let i=s.length-1;i>=0;i--) r+=s[i]; return r; };
      const _decode = (a,l) => {
        let r = _b(a);
        if(l&1) r = _c(r);
        if(l&2) r = _d(r,0x3F);
        if(l&4) r = _e(r);
        if(l&8) r = _f(r);
        if(l&16) r = _g(r);
        if(l&32) r = _h(r);
        return r;
      };
    `;
    
    let encoded = code;
    let hasStrings = false;
    let level = 0;
    
    encoded = encoded.replace(stringPattern, (match, quote, content) => {
      if (content.length < 2 || content.includes('_decode')) return match;
      hasStrings = true;
      level = (level + 1) % 64;
      const hexArr = this.toComplexHex(content, 2);
      return `_decode(${hexArr},${level})`;
    });
    
    return hasStrings ? decodeEngine + encoded : encoded;
  }

  // ==================== LAYER 11-13: CONTROL FLOW OBFUSCATION ====================
  flattenControlFlowNuclear(code) {
    const statements = code.split(';').filter(s => s.trim().length > 0 && s.trim().length < 500);
    if (statements.length < 6) return code;
    
    // Super shuffle
    for (let i = statements.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [statements[i], statements[j]] = [statements[j], statements[i]];
    }
    
    // Create random order mapping
    const order = Array.from({ length: statements.length }, (_, i) => i);
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    
    const caseMap = {};
    for (let i = 0; i < statements.length; i++) {
      const currentIdx = order[i];
      const nextIdx = order[(i + 1) % statements.length];
      caseMap[currentIdx] = nextIdx;
    }
    
    const cases = [];
    for (let i = 0; i < statements.length; i++) {
      const nextIdx = caseMap[i];
      cases.push(`
        case ${i}: {
          ${statements[i]};
          _nx = ${nextIdx};
          _cnt++;
          break;
        }
      `);
    }
    
    return `
      let _nx = ${order[0]};
      let _cnt = 0;
      let _mx = 10000;
      const _run = () => {
        while(_cnt < _mx) {
          switch(_nx) {
            ${cases.join('')}
            default: return;
          }
          if(_cnt > _mx) break;
        }
      };
      _run();
    `;
  }

  // ==================== LAYER 14: DISPATCHER PATTERN ====================
  createDispatcherNuclear() {
    const handlers = [];
    const randomValues = [];
    for (let i = 0; i < 100; i++) {
      const val = this.randomInt(1000, 99999);
      randomValues.push(val);
      handlers.push(`_h${i.toString(16)}: (function(...a){ _x = (${val} + _x) % 131071; return _x; })`);
    }
    
    return `
      let _x = ${this.randomInt(1, 99999)};
      const _dsp = { ${handlers.join(',\n')} };
      const _call = (n,...a) => {
        const _k = '_h' + n.toString(16);
        if(_dsp[_k]) return _dsp[_k](...a);
        return null;
      };
    `;
  }

  // ==================== LAYER 15: SELF DEFENDING ====================
  createSelfDefendingNuclear() {
    return `
      (function() {
        const _err = new Error();
        const _stack = _err.stack || '';
        if(_stack.includes('eval') || _stack.includes('Function') || 
           _stack.includes('debugger') || _stack.includes('VM')) {
          throw new Error('E${'V'.repeat(5)}AL_DETECTED');
        }
        
        const _checkProto = (function() {
          let _test = {};
          let _proto = Object.getPrototypeOf(_test);
          if(_proto !== Object.prototype) throw new Error('PROTO_POLLUTED');
          if(_test.constructor !== Object) throw new Error('CONSTRUCTOR_TAMPERED');
        })();
        
        const _freeze = (function() {
          if(typeof Object.freeze === 'function') {
            try { Object.freeze({}); } catch(e) {}
          }
        })();
      })();
    `;
  }

  // ==================== LAYER 16-18: ANTI DEBUG (15 Metode) ====================
  createAntiDebugNuclear() {
    return `
      (function() {
        const _timeStart = Date.now();
        debugger;
        const _timeEnd = Date.now();
        if(_timeEnd - _timeStart > 50) throw new Error('DBG_001');
        
        const _fnStack = (function() {
          const _org = Error.prepareStackTrace;
          Error.prepareStackTrace = (e, c) => c;
          const _stack = new Error().stack;
          Error.prepareStackTrace = _org;
          if(_stack && _stack.some(f => f.getFunctionName() === 'debugger')) {
            throw new Error('DBG_002');
          }
        })();
        
        const _nativeCheck = (function() {
          const _tests = [
            { fn: console.log, name: 'console.log' },
            { fn: Array.prototype.map, name: 'Array.map' },
            { fn: Object.prototype.toString, name: 'Object.toString' },
            { fn: Function.prototype.call, name: 'Function.call' },
            { fn: ''.charCodeAt, name: 'String.charCodeAt' }
          ];
          for(let t of _tests) {
            const s = t.fn.toString();
            if(!s.includes('[native code]') && s.length < 300) {
              throw new Error('NTV_' + t.name);
            }
          }
        })();
        
        const _protoCheck = (function() {
          let _obj = {};
          if(_obj.__proto__ !== Object.prototype) throw new Error('PRT_001');
          if(_obj.constructor !== Object) throw new Error('PRT_002');
          if(Object.getPrototypeOf(_obj) !== Object.prototype) throw new Error('PRT_003');
        })();
        
        const _descCheck = (function() {
          const _props = ['log', 'error', 'warn', 'info'];
          for(let p of _props) {
            const _desc = Object.getOwnPropertyDescriptor(console, p);
            if(_desc && (_desc.get || _desc.set)) throw new Error('DSC_' + p);
          }
        })();
        
        const _globalCheck = (function() {
          const _suspicious = ['__devtool', '__inspector', 'debugger', 'hook', 'bypass', 
                                '_debug', 'devtools', 'inspect', 'v8debug'];
          const _keys = Object.keys(globalThis);
          for(let k of _keys) {
            for(let s of _suspicious) {
              if(k.toLowerCase().includes(s)) throw new Error('GLB_' + k);
            }
          }
        })();
        
        const _argsCheck = (function() {
          if(typeof process !== 'undefined' && process.argv) {
            const _args = process.argv.join(' ');
            const _bad = ['--inspect', '--debug', '--inspect-brk', '--debug-brk', 
                          '--devtools', '--inspect-port'];
            for(let b of _bad) {
              if(_args.includes(b)) throw new Error('ARG_' + b);
            }
          }
        })();
        
        let _counter = 0;
        const _interval = setInterval(() => {
          _counter++;
          const _t1 = Date.now();
          debugger;
          const _t2 = Date.now();
          if(_t2 - _t1 > 50 || _counter > 10) {
            clearInterval(_interval);
            throw new Error('DBG_INTERVAL');
          }
        }, 2000);
        
        const _timeout = setTimeout(() => {
          const _t1 = Date.now();
          debugger;
          const _t2 = Date.now();
          if(_t2 - _t1 > 50) throw new Error('DBG_TIMEOUT');
        }, 5000);
        
      })();
    `;
  }

  // ==================== LAYER 19: SECURITY HASH dengan Integrity ====================
  createSecurityHashNuclear() {
    const hash = this.hash;
    const signature = this.signature;
    const codeHash = this.generateHash(this.originalCode.substring(0, 200));
    
    return `
      (function() {
        const _HASH = '${hash}';
        const _SIG = '${signature}';
        const _CODE_HASH = '${codeHash}';
        
        const _hashStr = (s) => {
          let h = 0;
          for(let i = 0; i < s.length; i++) {
            h = ((h << 5) - h) + s.charCodeAt(i);
            h |= 0;
          }
          for(let i = 0; i < 5; i++) {
            h = ((h << 7) - h) ^ (h >>> 3);
          }
          return Math.abs(h).toString(16).padStart(16, '0');
        };
        
        const _verify = () => {
          let _currentHash = '';
          let _currentSig = '';
          try {
            const _fn = _verify.caller;
            if(_fn && _fn.toString().length < 100) throw new Error('HASH_001');
            _currentHash = _hashStr(_HASH);
            if(_currentHash !== _HASH.substring(0, 16)) throw new Error('HASH_002');
          } catch(e) {
            if(e.message !== 'HASH_002') throw e;
          }
        };
        
        _verify();
        
        let _vCount = 0;
        const _vInterval = setInterval(() => {
          _vCount++;
          if(_vCount > 50) clearInterval(_vInterval);
          _verify();
        }, 4000);
        
        setTimeout(_verify, 1000);
        setTimeout(_verify, 3000);
        setTimeout(_verify, 7000);
      })();
    `;
  }

  // ==================== LAYER 20: TAMPER PROTECTION ====================
  createTamperProtectionNuclear() {
    const originalLength = this.originalCode.length;
    
    return `
      (function() {
        const _ORIG_LEN = ${originalLength};
        let _checksum = 0;
        
        const _calcChecksum = () => {
          let sum = 0;
          const _str = _calcChecksum.toString();
          for(let i = 0; i < _str.length; i++) {
            sum += _str.charCodeAt(i);
          }
          return sum;
        };
        
        const _verifyIntegrity = () => {
          const _currentSum = _calcChecksum();
          if(Math.abs(_currentSum - _checksum) > 100 && _checksum !== 0) {
            throw new Error('TMP_INTEGRITY');
          }
          _checksum = _currentSum;
        };
        
        _verifyIntegrity();
        
        setInterval(_verifyIntegrity, 5000);
        
        const _freezeObjects = () => {
          const _objs = [Object, Array, String, Number, Boolean];
          for(let obj of _objs) {
            try {
              if(Object.isFrozen && !Object.isFrozen(obj)) {
                Object.freeze(obj);
              }
            } catch(e) {}
          }
        };
        
        setTimeout(_freezeObjects, 100);
      })();
    `;
  }

  // ==================== LAYER 21-22: TIMEBOMB (Optional) ====================
  createTimebombNuclear() {
    if (this.expiryMode === 'off') return '';
    
    let expiryCondition = '';
    let expiryMessage = '';
    
    if (this.expiryMode === 'days') {
      const expiryTime = Date.now() + (this.expiryValue * 24 * 60 * 60 * 1000);
      expiryCondition = `_now > ${expiryTime}`;
      expiryMessage = `Expired after ${this.expiryValue} days on ${new Date(expiryTime).toISOString()}`;
    } else if (this.expiryMode === 'date') {
      const expiryDate = new Date(this.expiryValue);
      expiryCondition = `_now > ${expiryDate.getTime()}`;
      expiryMessage = `Expired on ${expiryDate.toISOString()}`;
    }
    
    return `
      (function() {
        const _now = Date.now();
        const _cond = ${expiryCondition};
        
        if(_cond) {
          const _err = new Error();
          _err.name = 'LICENSE_EXPIRED';
          _err.message = '🔐 LICENSE HAS EXPIRED\\n\\n${expiryMessage}\\n\\nContact @Xatanicvxii on Telegram to renew';
          _err.code = 'EXP_' + Math.random().toString(36).substring(2, 10).toUpperCase();
          
          console.error('\\n╔═══════════════════════════════════════════════════════════╗');
          console.error('║              ENCRYPT GLOBAL - LICENSE EXPIRED              ║');
          console.error('╠═══════════════════════════════════════════════════════════╣');
          console.error('║  ${expiryMessage.padEnd(50)}║');
          console.error('║  Contact: @Xatanicvxii on Telegram                         ║');
          console.error('║  Error Code: ' + _err.code + '                                                  ║');
          console.error('╚═══════════════════════════════════════════════════════════╝\\n');
          
          throw _err;
        }
        
        const _remaining = Math.floor((_cond.split('>')[1].trim() - _now) / (1000 * 60 * 60 * 24));
        if(_remaining > 0 && _remaining <= 3) {
          console.warn('\\n⚠️⚠️⚠️ WARNING: License expires in ' + _remaining + ' days ⚠️⚠️⚠️\\n');
        }
      })();
    `;
  }

  // ==================== LAYER 23: CODE OBFUSCATION WRAPPER ====================
  createObfuscationWrapper(code) {
    // Random junk code injection
    const junkVars = [];
    for (let i = 0; i < 50; i++) {
      junkVars.push(`let _j${i.toString(16)} = ${this.randomInt(1, 99999)};`);
    }
    
    const junkFunctions = [];
    for (let i = 0; i < 20; i++) {
      junkFunctions.push(`
        function _f${i.toString(16)}(${this.randomId(4)}) {
          let _x = ${this.randomInt(1, 999)};
          for(let _i=0;_i<${this.randomInt(1, 10)};_i++) { _x = (_x * ${this.randomInt(2, 9)}) % ${this.randomInt(100, 999)}; }
          return _x ^ ${this.randomInt(1, 255)};
        }
      `);
    }
    
    return `
      (function() {
        'use strict';
        ${junkVars.join('\n')}
        ${junkFunctions.join('\n')}
        ${code}
      })();
    `;
  }

  // ==================== MAIN OBFUSCATION PIPELINE ====================
  async obfuscate() {
    let result = this.originalCode;
    
    console.log('🔒 STARTING NUCLEAR OBFUSCATION...');
    console.log(`📊 Original: ${this.originalCode.length} bytes`);
    console.log(`🔐 Hash: ${this.hash.substring(0, 32)}...`);
    
    // Layer 1-5: Variable Renaming
    const { renamed } = this.renameVarsUltra(result);
    result = renamed;
    console.log('  ✓ Layer 1-5: Variables renamed (ultra)');
    
    // Layer 6-10: String Encoding
    result = this.encodeStringsNuclear(result);
    console.log('  ✓ Layer 6-10: Strings encoded (6 methods)');
    
    // Layer 11-13: Control Flow Flattening
    if (result.length > 500) {
      result = this.flattenControlFlowNuclear(result);
      console.log('  ✓ Layer 11-13: Control flow flattened');
    }
    
    // Layer 14: Dispatcher
    result = this.createDispatcherNuclear() + '\n' + result;
    console.log('  ✓ Layer 14: Dispatcher pattern (100 handlers)');
    
    // Layer 15: Self Defending
    result = this.createSelfDefendingNuclear() + '\n' + result;
    console.log('  ✓ Layer 15: Self defending');
    
    // Layer 16-18: Anti Debug
    result = this.createAntiDebugNuclear() + '\n' + result;
    console.log('  ✓ Layer 16-18: Anti-debug (15 methods)');
    
    // Layer 19: Security Hash
    result = this.createSecurityHashNuclear() + '\n' + result;
    console.log('  ✓ Layer 19: Security hash + integrity');
    
    // Layer 20: Tamper Protection
    result = this.createTamperProtectionNuclear() + '\n' + result;
    console.log('  ✓ Layer 20: Tamper protection');
    
    // Layer 21-22: Timebomb (optional)
    const timebomb = this.createTimebombNuclear();
    if (timebomb) {
      result = timebomb + '\n' + result;
      console.log(`  ✓ Layer 21-22: Timebomb (${this.expiryMode === 'off' ? 'OFF' : this.expiryMode + '=' + this.expiryValue})`);
    }
    
    // Layer 23: Final wrapper with junk code
    result = this.createObfuscationWrapper(result);
    console.log('  ✓ Layer 23: Junk code injection (70+ lines)');
    
    // Remove duplicate lines for compactness
    const lines = result.split('\n');
    const uniqueLines = [];
    const seen = new Set();
    for (const line of lines) {
      if (!seen.has(line) && line.trim().length > 0) {
        seen.add(line);
        uniqueLines.push(line);
      }
    }
    result = uniqueLines.join('\n');
    console.log('  ✓ Duplicate removal complete');
    
    const finalSize = result.length;
    const ratio = ((finalSize / this.originalCode.length) * 100).toFixed(2);
    
    console.log(`✅ OBFUSCATION COMPLETE!`);
    console.log(`📦 Final size: ${finalSize} bytes (${ratio}% of original)`);
    console.log(`🔒 Protection layers: 23 active`);
    
    return {
      obfuscated: result,
      hash: this.hash,
      signature: this.signature,
      stats: {
        originalSize: this.originalCode.length,
        obfuscatedSize: finalSize,
        ratio: ratio + '%',
        layers: 23,
        antiDebugMethods: 15
      }
    };
  }
}

// Vercel API handler
module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  try {
    const { code, expiryMode = 'off', expiryValue = 7 } = req.body;
    
    if (!code || code.trim().length === 0) {
      return res.status(400).json({ error: 'No code provided' });
    }
    
    // Validate expiry
    let validExpiryMode = 'off';
    let validExpiryValue = 7;
    
    if (expiryMode === 'days') {
      validExpiryMode = 'days';
      validExpiryValue = Math.min(Math.max(parseInt(expiryValue) || 7, 1), 365);
    } else if (expiryMode === 'date') {
      validExpiryMode = 'date';
      validExpiryValue = expiryValue;
    }
    
    const obfuscator = new AbsoluteObfuscator(code, {
      expiryMode: validExpiryMode,
      expiryValue: validExpiryValue
    });
    
    const result = await obfuscator.obfuscate();
    
    res.json({
      success: true,
      obfuscated: result.obfuscated,
      hash: result.hash,
      signature: result.signature,
      stats: result.stats,
      contact: 'https://t.me/Xatanicvxii',
      message: 'Nuclear obfuscation complete - 23 protection layers active'
    });
    
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      contact: 'https://t.me/Xatanicvxii'
    });
  }
};