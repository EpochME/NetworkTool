/**
 * ==============================================================================
 * 📌 脚本名称 (Script Name) : SecureCrypto (跨平台高安全加解密工具)
 * 📌 脚本版本 (Version)     : v5.5 (Quantumult X / 无 BigInt 强化优化版)
 * 📌 作者/贡献 (Author)     : Anonymous
 * 
 * ------------------------------------------------------------------------------
 * 📝 功能描述 (Description):
 * 本脚本为一个完全基于原生 JavaScript 实现的高强度、无外部依赖的纯算法加解密工具。
 * 面向 Quantumult X、Loon、Surge、Node.js、浏览器等现代 JavaScript 环境；不依赖 BigInt；宿主仍需提供标准 TypedArray 与安全随机源（CSPRNG）。
 * 
 * 🔐 核心安全标准 (Security Standards):
 * 1. 统一密码协议                 : 不再根据宿主环境切换 AES/ChaCha，v5.4 所有平台统一使用 RFC 8439 ChaCha20-Poly1305。
 * 2. 算法协议标识 (Version Header) : 密文头部注入算法标识 (v5.4: RFC 8439 ChaCha20-Poly1305)，解决跨环境解密失败。
 * 3. 密钥派生 (KDF)               : PBKDF2-HMAC-SHA256（默认 100,000 次，参数写入密文），防范暴力破解。
 * 4. 内存安全 (Zeroize)           : 尽可能对可变 TypedArray 执行零化清理（JavaScript 无法保证字符串内存真正清零）。
 * 
 * ⚙️ 核心配置说明 (CONFIG Options):
 * - mode          : 运行模式 ("encrypt" 加密 / "decrypt" 解密)。
 * - key           : 解密/加密所使用的密钥密码。
 * - plaintext     : 加密模式下的待加密明文。
 * - ciphertext    : 解密模式下的待解密 Base64 密文。
 * - enableNotify  : 是否开启客户端应用内弹窗通知 ($notify)。
 * - logSensitive  : 是否在日志中打印解密后的敏感明文。\n * - notifySensitive : 是否允许 $notify 显示完整解密明文（默认 false）。\n * - pbkdf2Iterations : PBKDF2-HMAC-SHA256 迭代次数，写入密文。
 * ==============================================================================
 */

const CONFIG = {
    mode: "encrypt",      // "encrypt" 或 "decrypt"
    key: "AAA", 
    plaintext: "Hello, Quantumult X! 🚀🥑 v5.5", 
    ciphertext: "", 
    enableNotify: true,   // 是否开启通知
    logSensitive: false,  // 是否在日志打印明文
    notifySensitive: true, // 是否允许通知显示完整明文
    pbkdf2Iterations: 100000 // PBKDF2-HMAC-SHA256 迭代次数
};


const SecureCrypto = (function () {
    // =========================================================================
    // SecureCrypto v5.5
    // - 统一使用 RFC 8439 ChaCha20-Poly1305，所有平台走同一协议
    // - 使用 CSPRNG；没有安全随机源时直接失败，禁止 Math.random()
    // - PBKDF2-HMAC-SHA256，迭代次数写入密文，便于未来升级
    // - 密文格式：
    //   [0x53 'S'][0x43 'C'][0x03 version][0x01 alg]
    //   [4B KDF iterations BE][16B salt][12B nonce][16B tag][ciphertext]
    // =========================================================================

    const MAGIC_S = 0x53; // S
    const MAGIC_C = 0x43; // C
    const VERSION = 0x03;
    const ALG_CHACHA20_POLY1305 = 0x01;
    const KDF_PBKDF2_SHA256 = 0x01;
    const SALT_LEN = 16;
    const NONCE_LEN = 12;
    const TAG_LEN = 16;
    const HEADER_LEN = 2 + 1 + 1 + 4 + SALT_LEN + NONCE_LEN + TAG_LEN;
    const DEFAULT_PBKDF2_ITERATIONS = 100000;
    const MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;

    const SHA256_W = new Int32Array(64);
    const HMAC_IKEY = new Uint8Array(64);
    const HMAC_OKEY = new Uint8Array(64);
    const HMAC_INNER_BUF = new Uint8Array(64 + 128);
    const HMAC_OUTER_BUF = new Uint8Array(64 + 32);
    const SHA256_MSG_BUF = new Uint8Array(256);
    const INNER_HASH = new Uint8Array(32);

    const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const B64_LOOKUP = new Uint8Array(256);
    B64_LOOKUP.fill(255);
    for (let i = 0; i < B64_CHARS.length; i++) B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;

    function getRandomBytes(length) {
        const bytes = new Uint8Array(length);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(bytes);
            return bytes;
        }
        if (typeof require !== 'undefined') {
            try {
                const nodeCrypto = require('crypto');
                bytes.set(nodeCrypto.randomBytes(length));
                return bytes;
            } catch (e) {}
        }
        // 安全工具宁可失败，也不能用 Math.random() 生成 salt/nonce。
        throw new Error("当前运行环境没有可用的密码学安全随机数源（CSPRNG），已拒绝继续加密。");
    }

    function constantTimeAreEqual(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let res = 0;
        for (let i = 0; i < a.length; i++) res |= (a[i] ^ b[i]);
        return res === 0;
    }

    function zeroize(target) {
        if (!target) return;
        if (target.fill) target.fill(0);
        else for (let i = 0; i < target.length; i++) target[i] = 0;
    }

    function utf8ToBytes(str) {
        if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
            let code = str.charCodeAt(i);
            if (code < 0x80) bytes.push(code);
            else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
            else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
                let next = str.charCodeAt(i + 1);
                if (next >= 0xdc00 && next <= 0xdfff) {
                    i++;
                    code = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
                    bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f),
                        0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
                } else bytes.push(0xef, 0xbf, 0xbd);
            } else bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
        return new Uint8Array(bytes);
    }

    function bytesToUtf8(bytes) {
        if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
        let str = '', i = 0;
        while (i < bytes.length) {
            let c = bytes[i++];
            if (c > 127) {
                if (c > 191 && c < 224) c = ((c & 31) << 6) | (bytes[i++] & 63);
                else if (c > 223 && c < 240) c = ((c & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
                else if (c > 239 && c < 248) c = ((c & 7) << 18) | ((bytes[i++] & 63) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
            }
            if (c <= 0xffff) str += String.fromCharCode(c);
            else {
                c -= 0x10000;
                str += String.fromCharCode((c >> 10) | 0xd800, (c & 0x3ff) | 0xdc00);
            }
        }
        return str;
    }

    function bytesToBase64(bytes) {
        let result = "", i = 0, len = bytes.length;
        for (; i < len - 2; i += 3) {
            result += B64_CHARS[bytes[i] >> 2];
            result += B64_CHARS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            result += B64_CHARS[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            result += B64_CHARS[bytes[i + 2] & 63];
        }
        if (i < len) {
            result += B64_CHARS[bytes[i] >> 2];
            if (i === len - 1) result += B64_CHARS[(bytes[i] & 3) << 4] + "==";
            else result += B64_CHARS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)] +
                B64_CHARS[(bytes[i + 1] & 15) << 2] + "=";
        }
        return result;
    }

    function base64ToBytes(str) {
        if (typeof str !== "string" || !str || /[^A-Za-z0-9+/=\s]/.test(str)) {
            throw new Error("Base64 字符串包含非法字符");
        }
        const cleanStr = str.replace(/\s+/g, "");
        if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) throw new Error("Base64 长度非法");
        const firstPad = cleanStr.indexOf("=");
        if (firstPad >= 0) {
            if (firstPad < cleanStr.length - 2 || /[^=]/.test(cleanStr.slice(firstPad))) {
                throw new Error("Base64 padding 非法");
            }
        }
        const len = cleanStr.length;
        const targetLen = (len * 3) / 4 - (cleanStr.endsWith("==") ? 2 : cleanStr.endsWith("=") ? 1 : 0);
        // RFC 4648 canonical Base64：padding 后未使用的比特必须为 0。
        if (cleanStr.endsWith("==")) {
            const last = B64_LOOKUP[cleanStr.charCodeAt(len - 3)];
            if ((last & 15) !== 0) throw new Error("Base64 尾部填充位非法");
        } else if (cleanStr.endsWith("=")) {
            const last = B64_LOOKUP[cleanStr.charCodeAt(len - 2)];
            if ((last & 3) !== 0) throw new Error("Base64 尾部填充位非法");
        }
        const bytes = new Uint8Array(targetLen);
        let ptr = 0;
        for (let i = 0; i < len; i += 4) {
            const c1 = cleanStr.charCodeAt(i), c2 = cleanStr.charCodeAt(i + 1);
            const c3c = cleanStr[i + 2], c4c = cleanStr[i + 3];
            const b1 = B64_LOOKUP[c1], b2 = B64_LOOKUP[c2];
            const b3 = c3c === "=" ? 0 : B64_LOOKUP[cleanStr.charCodeAt(i + 2)];
            const b4 = c4c === "=" ? 0 : B64_LOOKUP[cleanStr.charCodeAt(i + 3)];
            if (b1 > 63 || b2 > 63 || b3 > 63 || b4 > 63) throw new Error("Base64 内容非法");
            bytes[ptr++] = (b1 << 2) | (b2 >> 4);
            if (ptr < targetLen) bytes[ptr++] = ((b2 & 15) << 4) | (b3 >> 2);
            if (ptr < targetLen) bytes[ptr++] = ((b3 & 3) << 6) | b4;
        }
        return bytes;
    }

    const SHA256_K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function sha256ToBuffer(bytes, outBuffer) {
        let l = bytes.length, bitLen = l * 8, newLen = ((l + 9 + 63) >> 6) << 6;
        let msg = newLen <= SHA256_MSG_BUF.length ? SHA256_MSG_BUF : new Uint8Array(newLen);
        msg.fill(0);
        
        try {
            msg.set(bytes); msg[l] = 0x80;
            let view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength); 
            view.setUint32(newLen - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);
            view.setUint32(newLen - 4, bitLen & 0xffffffff, false);
            let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
            
            for (let i = 0; i < newLen; i += 64) {
                for (let t = 0; t < 16; t++) SHA256_W[t] = view.getInt32(i + t * 4, false);
                for (let t = 16; t < 64; t++) {
                    let w15 = SHA256_W[t - 15], w2 = SHA256_W[t - 2];
                    let s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
                    let s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
                    SHA256_W[t] = (SHA256_W[t - 16] + s0 + SHA256_W[t - 7] + s1) | 0;
                }
                let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
                for (let t = 0; t < 64; t++) {
                    let S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                    let ch = (e & f) ^ ((~e) & g);
                    let temp1 = (h + S1 + ch + SHA256_K[t] + SHA256_W[t]) | 0;
                    let S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let temp2 = (S0 + maj) | 0;
                    h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
                }
                H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
                H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
            }
            for (let i = 0; i < 8; i++) {
                outBuffer[i * 4] = (H[i] >>> 24) & 0xff;
                outBuffer[i * 4 + 1] = (H[i] >>> 16) & 0xff;
                outBuffer[i * 4 + 2] = (H[i] >>> 8) & 0xff;
                outBuffer[i * 4 + 3] = H[i] & 0xff;
            }
        } finally {
            if (msg !== SHA256_MSG_BUF) zeroize(msg);
        }
    }

    function hmacSha256InPlace(key, message, outBuffer) {
        let actualKey=key, hashedKey=null;
        if(key.length>64){hashedKey=new Uint8Array(32);sha256ToBuffer(key,hashedKey);actualKey=hashedKey;}
        HMAC_OKEY.fill(0x5c);HMAC_IKEY.fill(0x36);
        for(let i=0;i<actualKey.length;i++){HMAC_OKEY[i]^=actualKey[i];HMAC_IKEY[i]^=actualKey[i];}
        if(message.length>128) throw new Error("HMAC 内部消息块过长");
        HMAC_INNER_BUF.fill(0);HMAC_INNER_BUF.set(HMAC_IKEY);HMAC_INNER_BUF.set(message,64);
        sha256ToBuffer(HMAC_INNER_BUF.subarray(0,64+message.length),INNER_HASH);
        HMAC_OUTER_BUF.fill(0);HMAC_OUTER_BUF.set(HMAC_OKEY);HMAC_OUTER_BUF.set(INNER_HASH,64);
        sha256ToBuffer(HMAC_OUTER_BUF.subarray(0,96),outBuffer);
        zeroize(HMAC_IKEY);zeroize(HMAC_OKEY);zeroize(INNER_HASH);
        if(hashedKey)zeroize(hashedKey);HMAC_INNER_BUF.fill(0);HMAC_OUTER_BUF.fill(0);
    }

    function pbkdf2Sync(password, salt, iterations, keyLen) {
        if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 0xffffffff) throw new Error("PBKDF2 迭代次数非法");
        const pwBytes=utf8ToBytes(password), derivedKey=new Uint8Array(keyLen);
        const saltWithIndex=new Uint8Array(salt.length+4), U=new Uint8Array(32), T=new Uint8Array(32);
        saltWithIndex.set(salt); let offset=0,blockIndex=1;
        try{
            const dv=new DataView(saltWithIndex.buffer);
            while(offset<keyLen){
                dv.setUint32(salt.length,blockIndex,false);
                hmacSha256InPlace(pwBytes,saltWithIndex,U);T.set(U);
                for(let i=1;i<iterations;i++){hmacSha256InPlace(pwBytes,U,U);for(let j=0;j<32;j++)T[j]^=U[j];}
                const writeLen=Math.min(32,keyLen-offset);derivedKey.set(T.subarray(0,writeLen),offset);
                offset+=writeLen;blockIndex++;
            }
            return derivedKey;
        }finally{zeroize(pwBytes);zeroize(saltWithIndex);zeroize(U);zeroize(T);}
    }

    function rotl(v,n){return (v<<n)|(v>>>(32-n));}

    // RFC 8439 ChaCha20: 20 rounds = 10 double-rounds.
    function chacha20Block(key,counter,nonce){
        const state=new Uint32Array(16);
        state[0]=0x61707865;state[1]=0x3320646e;state[2]=0x79622d32;state[3]=0x6b206574;
        for(let i=0;i<8;i++)state[4+i]=(key[i*4]|(key[i*4+1]<<8)|(key[i*4+2]<<16)|(key[i*4+3]<<24))>>>0;
        state[12]=counter>>>0;
        for(let i=0;i<3;i++)state[13+i]=(nonce[i*4]|(nonce[i*4+1]<<8)|(nonce[i*4+2]<<16)|(nonce[i*4+3]<<24))>>>0;
        const x=new Uint32Array(state);
        function qr(a,b,c,d){
            x[a]=(x[a]+x[b])>>>0;x[d]=rotl(x[d]^x[a],16)>>>0;
            x[c]=(x[c]+x[d])>>>0;x[b]=rotl(x[b]^x[c],12)>>>0;
            x[a]=(x[a]+x[b])>>>0;x[d]=rotl(x[d]^x[a],8)>>>0;
            x[c]=(x[c]+x[d])>>>0;x[b]=rotl(x[b]^x[c],7)>>>0;
        }
        for(let i=0;i<10;i++){
            qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);
            qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14);
        }
        const out=new Uint8Array(64);
        for(let i=0;i<16;i++){const v=(x[i]+state[i])>>>0;out[i*4]=v&255;out[i*4+1]=(v>>>8)&255;out[i*4+2]=(v>>>16)&255;out[i*4+3]=(v>>>24)&255;}
        zeroize(state);zeroize(x);
        return out;
    }

    function chacha20Encrypt(key,counter,nonce,data){
        const out=new Uint8Array(data.length);
        for(let off=0,ctr=counter;off<data.length;off+=64,ctr++){
            const block=chacha20Block(key,ctr,nonce), n=Math.min(64,data.length-off);
            for(let j=0;j<n;j++)out[off+j]=data[off+j]^block[j];
            zeroize(block);
        }
        return out;
    }

    // Standard Poly1305 without BigInt.
    // Uses 10 limbs in base 2^13. All intermediate products stay safely below 2^53.
    function poly1305Tag(msg, key) {
        const BASE = 8192;

        function bytesToLimbs16(bytes) {
            const limbs = new Array(10).fill(0);
            for (let bi = 15; bi >= 0; bi--) {
                let carry = bytes[bi];
                for (let i = 0; i < 10; i++) {
                    const v = limbs[i] * 256 + carry;
                    limbs[i] = v % BASE;
                    carry = Math.floor(v / BASE);
                }
            }
            return limbs;
        }

        function limbsToBytes128(limbs) {
            const out = new Uint8Array(16);
            // 10×13-bit limbs → 16 bytes；避免逐 bit 扫描。
            for (let byteIndex = 0; byteIndex < 16; byteIndex++) {
                const bit = byteIndex * 8;
                const limbIndex = Math.floor(bit / 13);
                const shift = bit - limbIndex * 13;
                let v = Math.floor(limbs[limbIndex] / Math.pow(2, shift));
                if (shift > 5 && limbIndex + 1 < 10) v += limbs[limbIndex + 1] * Math.pow(2, 13 - shift);
                out[byteIndex] = v & 255;
            }
            return out;
        }

        // RFC 8439 Poly1305 clamp.
        const rBytes = new Uint8Array(key.subarray(0, 16));
        rBytes[3] &= 15;
        rBytes[7] &= 15;
        rBytes[11] &= 15;
        rBytes[15] &= 15;
        rBytes[4] &= 252;
        rBytes[8] &= 252;
        rBytes[12] &= 252;

        const r = bytesToLimbs16(rBytes);
        const s = key.subarray(16, 32);
        const h = new Array(10).fill(0);

        const block = new Uint8Array(16);
        const m = new Array(10).fill(0);
        const t = new Array(19).fill(0);
        try {
            for (let off = 0; off < msg.length; off += 16) {
                const n = Math.min(16, msg.length - off);
                block.fill(0);
                block.set(msg.subarray(off, off + n));
                const parsed = bytesToLimbs16(block);
                for (let i = 0; i < 10; i++) m[i] = parsed[i];
                zeroize(parsed);

                // Add the implicit 1 bit: block || 0x01 in little-endian form.
                const oneBit = n * 8;
                const oneIndex = Math.floor(oneBit / 13);
                const oneShift = oneBit % 13;
                if (oneIndex < 10) m[oneIndex] += Math.pow(2, oneShift);

                for (let i = 0; i < 10; i++) h[i] += m[i];

                // h = (h * r) mod (2^130 - 5), with BASE^10 == 5 (mod p).
                for (let i = 0; i < 19; i++) t[i] = 0;
                for (let i = 0; i < 10; i++) {
                    for (let j = 0; j < 10; j++) {
                        t[i + j] += h[i] * r[j];
                    }
                }

                for (let k = 18; k >= 10; k--) {
                    t[k - 10] += t[k] * 5;
                }

                for (let i = 0; i < 10; i++) h[i] = t[i];

                // Normalize and fold the carry from limb 9 back into limb 0.
                for (let round = 0; round < 3; round++) {
                    for (let i = 0; i < 9; i++) {
                        const carry = Math.floor(h[i] / BASE);
                        h[i] -= carry * BASE;
                        h[i + 1] += carry;
                    }
                    const carry9 = Math.floor(h[9] / BASE);
                    h[9] -= carry9 * BASE;
                    h[0] += carry9 * 5;
                }

                zeroize(block);
                zeroize(m);
            }

            // Conditional subtraction of p = 2^130 - 5.
            const pLimbs = new Array(10).fill(BASE - 1);
            pLimbs[0] = BASE - 5;
            let geP = true;
            for (let i = 9; i >= 0; i--) {
                if (h[i] !== pLimbs[i]) {
                    geP = h[i] > pLimbs[i];
                    break;
                }
            }
            if (geP) {
                h[0] -= 5;
                for (let i = 0; i < 9; i++) {
                    if (h[i] < 0) {
                        h[i] += BASE;
                        h[i + 1]--;
                    }
                }
            }

            // Add s modulo 2^128, byte-by-byte to avoid >53-bit arithmetic.
            const h128 = limbsToBytes128(h);
            const tag = new Uint8Array(16);
            let carry = 0;
            for (let i = 0; i < 16; i++) {
                const sum = h128[i] + s[i] + carry;
                tag[i] = sum & 255;
                carry = Math.floor(sum / 256);
            }
            zeroize(h128);
            return tag;
        } finally {
            zeroize(rBytes);
            zeroize(r);
            zeroize(h);
            zeroize(block);
            zeroize(m);
            zeroize(t);
        }
    }
    function load32le(b,i){return (b[i]|(b[i+1]<<8)|(b[i+2]<<16)|(b[i+3]<<24))>>>0;}
    function store32le(b,i,v){b[i]=v&255;b[i+1]=(v>>>8)&255;b[i+2]=(v>>>16)&255;b[i+3]=(v>>>24)&255;}
    function le64toBytes(n){const b=new Uint8Array(8);let x=n;for(let i=0;i<8;i++){b[i]=x%256;x=Math.floor(x/256);}return b;}

    function concatParts(parts){
        let len=0;for(const p of parts)len+=p.length;
        const out=new Uint8Array(len);let off=0;
        for(const p of parts){out.set(p,off);off+=p.length;}
        return out;
    }
    function buildAeadMacData(aad,cipher){
        const ap=(16-(aad.length%16))%16, cp=(16-(cipher.length%16))%16;
        const pa=new Uint8Array(ap),pc=new Uint8Array(cp);
        const la=le64toBytes(aad.length),lc=le64toBytes(cipher.length);
        const out=concatParts([aad,pa,cipher,pc,la,lc]);
        zeroize(pa);zeroize(pc);zeroize(la);zeroize(lc);
        return out;
    }

    function makePayload(plaintext,password){
        const salt=getRandomBytes(SALT_LEN),nonce=getRandomBytes(NONCE_LEN);
        const iterations = Number(CONFIG.pbkdf2Iterations || DEFAULT_PBKDF2_ITERATIONS);
        if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 0xffffffff) throw new Error("CONFIG.pbkdf2Iterations 必须为 1000～4294967295 的整数");
        let key=null,polyBlock=null,polyKey=null,plain=null,cipher=null,macData=null,tag=null;
        try{
            key=pbkdf2Sync(password,salt,iterations,32);
            polyBlock=chacha20Block(key,0,nonce);polyKey=new Uint8Array(polyBlock.subarray(0,32));
            plain=utf8ToBytes(plaintext);cipher=chacha20Encrypt(key,1,nonce,plain);
            macData=buildAeadMacData(new Uint8Array(0),cipher);tag=poly1305Tag(macData,polyKey);
            if (HEADER_LEN + cipher.length > MAX_CIPHERTEXT_BYTES) throw new Error("明文过大：超过 16 MiB 安全处理上限");
            const payload=new Uint8Array(HEADER_LEN+cipher.length);
            payload[0]=MAGIC_S;payload[1]=MAGIC_C;payload[2]=VERSION;payload[3]=ALG_CHACHA20_POLY1305;
            const dv=new DataView(payload.buffer);dv.setUint32(4,iterations,false);
            payload.set(salt,8);payload.set(nonce,24);payload.set(tag,36);payload.set(cipher,52);
            return bytesToBase64(payload);
        }finally{zeroize(key);zeroize(polyBlock);zeroize(polyKey);zeroize(plain);zeroize(cipher);zeroize(macData);zeroize(tag);zeroize(salt);zeroize(nonce);}
    }

    function parsePayload(ciphertext){
        const p=base64ToBytes(ciphertext);
        if(p.length > MAX_CIPHERTEXT_BYTES) throw new Error("密文超过安全处理上限（16 MiB）");
        if(p.length<HEADER_LEN)throw new Error("密文格式非法或已损坏");
        if(p[0]!==MAGIC_S||p[1]!==MAGIC_C||p[2]!==VERSION)throw new Error("不支持的密文版本：仅支持 SecureCrypto v5.5 密文");
        if(p[3]!==ALG_CHACHA20_POLY1305)throw new Error("不支持的加密算法标识");
        const dv=new DataView(p.buffer,p.byteOffset,p.byteLength),iterations=dv.getUint32(4,false);
        if(iterations<1000)throw new Error("密文中的 PBKDF2 参数非法");
        return {payload:p,iterations,salt:p.subarray(8,24),nonce:p.subarray(24,36),tag:p.subarray(36,52),cipher:p.subarray(52)};
    }

    function decryptPayload(ciphertext,password){
        const x=parsePayload(ciphertext),key=pbkdf2Sync(password,x.salt,x.iterations,32);
        let polyBlock=null,polyKey=null,macData=null,computed=null,plain=null;
        try{
            polyBlock=chacha20Block(key,0,x.nonce);polyKey=new Uint8Array(polyBlock.subarray(0,32));
            macData=buildAeadMacData(new Uint8Array(0),x.cipher);computed=poly1305Tag(macData,polyKey);
            if(!constantTimeAreEqual(x.tag,computed))throw new Error("密钥不匹配或密文已被篡改！");
            plain=chacha20Encrypt(key,1,x.nonce,x.cipher);
            return bytesToUtf8(plain);
        }finally{zeroize(key);zeroize(polyBlock);zeroize(polyKey);zeroize(macData);zeroize(computed);zeroize(plain);}
    }

    return {
        encryptAsync: async function(plaintext,password){ return this.encryptSync(plaintext,password); },
        decryptAsync: async function(ciphertext,password){ return this.decryptSync(ciphertext,password); },
        encryptSync: function(plaintext,password){ return makePayload(plaintext,password); },
        decryptSync: function(ciphertext,password){ return decryptPayload(ciphertext,password); }
    };
})();
function safeLog(str) {
    if (typeof str !== "string") str = String(str);
    const cleanStr = str.replace(/[\x00-\x09\x0B-\x1F\x7F-\x9F]/g, "");
    console.log(cleanStr);
}

function sendNotification(title, subtitle, detail) {
    if (CONFIG.enableNotify && typeof $notify !== "undefined") {
        $notify(title, subtitle, detail);
    }
}

async function main() {
    const cleanKey = (CONFIG.key || "").trim();
    if (!cleanKey) {
        sendNotification("🔒 密码工具", "❌ 错误", "请先在 CONFIG 中设置密钥 key");
        if (typeof $done !== "undefined") $done();
        return;
    }

    try {
        if (CONFIG.mode === "encrypt") {
            if (!CONFIG.plaintext) {
                throw new Error("请先在 CONFIG.plaintext 中配置待加密的明文数据");
            }

            const encrypted = await SecureCrypto.encryptAsync(CONFIG.plaintext, cleanKey);
            
            safeLog("\n==================== 🔐 密文结果 ====================\n");
            safeLog(encrypted);
            safeLog("\n====================================================\n");

            sendNotification("🔐 加密成功", "请在脚本 Log 中复制 Base64 密文", encrypted);

        } else if (CONFIG.mode === "decrypt") {
            const cleanCiphertext = (CONFIG.ciphertext || "").trim();
            if (!cleanCiphertext) {
                throw new Error("请先在 CONFIG.ciphertext 中填入待解密的 Base64 密文");
            }

            const decrypted = await SecureCrypto.decryptAsync(cleanCiphertext, cleanKey);
            
            safeLog("\n==================== 🔓 解密结果 ====================\n");
            if (CONFIG.logSensitive) {
                safeLog(decrypted);
            } else {
                safeLog(`[已解密成功，明文长度: ${decrypted.length} 字符] (日志明文已隐蔽)`);
            }
            safeLog("\n====================================================\n");

            sendNotification("🔓 解密成功", "明文已解密", CONFIG.notifySensitive ? decrypted : `[已解密成功，明文长度: ${decrypted.length} 字符]`);
        } else {
            throw new Error(`未知的运行模式 CONFIG.mode: "${CONFIG.mode}"`);
        }
    } catch (e) {
        safeLog(`\n❌ 执行失败: ${e.message}\n`);
        sendNotification("❌ 操作失败", "错误原因", e.message);
    } finally {
        if (typeof $done !== "undefined") $done();
    }
}

main();
