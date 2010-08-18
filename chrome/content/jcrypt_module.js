
// Cryptography module, to be loaded via Components.utils.import

var prng;
var jcrypt  = {
    
  initialized : false,
  
  include : function(src) {
    var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].getService(Components.interfaces.mozIJSSubScriptLoader);
    loader.loadSubScript("chrome://cryptfire/content/javascrypt/"+src);
  },

  init : function() {
        this.include("aes.js");
        this.include("aesprng.js");
        this.include("armour.js");
        this.include("entropy.js");
        this.include("lecuyer.js");
        this.include("md5.js");
        this.include("stegodict.js");
        this.include("utf-8.js");
        ce();
        
  },
  
  addEntropy : function(doc) {
        mouseMotionEntropy(60, doc);
  },
  
  
    loadTime : (new Date()).getTime(),  // Save time page was loaded
    key : null,	     // Key (byte array)
    rememberedPass : "",
    
    rememberPass : function(pass) {
        this.rememberedPass = pass;
    },
    
    getRememberedPass : function() {
        return this.rememberedPass;
    },
    
    //	setKey  --  Set key from string or hexadecimal specification
    
    setKey : function(newKey) {
    	    var s = encode_utf8(newKey);
	    var i, kmd5e, kmd5o;

	    if (s.length == 1) {
	    	s += s;
	    }
	    
	    md5_init();
	    for (i = 0; i < s.length; i += 2) {
	    	md5_update(s.charCodeAt(i));
	    }
	    md5_finish();
	    kmd5e = byteArrayToHex(digestBits);
	    
	    md5_init();
	    for (i = 1; i < s.length; i += 2) {
	    	md5_update(s.charCodeAt(i));
	    }
	    md5_finish();
	    kmd5o = byteArrayToHex(digestBits);

	    var hs = kmd5e + kmd5o;
	    this.key =  hexToByteArray(hs);
	    hs = byteArrayToHex(this.key);
    },
    
    encryptText : function(plain, key) {
	var v, i;
	var prefix = "-- Encrypted: decrypt with http://cryptfire.com/\n",
        suffix = "--  End encrypted message\n";
	
    	this.setKey(key);

	addEntropyTime();
    	prng = new AESprng(keyFromEntropy());
	var plaintext = encode_utf8(plain);
	
	//  Compute MD5 sum of message text and add to header
	
	md5_init();
	for (i = 0; i < plaintext.length; i++) {
	    md5_update(plaintext.charCodeAt(i));
	}
	md5_finish();
	var header = "";
	for (i = 0; i < digestBits.length; i++) {
	    header += String.fromCharCode(digestBits[i]);
	}
	
	//  Add message length in bytes to header
	
	i = plaintext.length;
	header += String.fromCharCode(i >>> 24);
	header += String.fromCharCode(i >>> 16);
	header += String.fromCharCode(i >>> 8);
	header += String.fromCharCode(i & 0xFF);

    	/*  The format of the actual message passed to rijndaelEncrypt
	    is:
	    
	    	    Bytes   	Content
		     0-15   	MD5 signature of plaintext
		    16-19   	Length of plaintext, big-endian order
		    20-end  	Plaintext
		    
	    Note that this message will be padded with zero bytes
	    to an integral number of AES blocks (blockSizeInBits / 8).
	    This does not include the initial vector for CBC
	    encryption, which is added internally by rijndaelEncrypt.
	    
	*/

	var ct = rijndaelEncrypt(header + plaintext, this.key, "CBC");
    	v = armour_base64(ct);
	var result = prefix + v + suffix;
    	delete prng;
        return result;
    },
    
    decryptText : function(cipher, plainkey) {
    	this.setKey(plainkey);
	var ct = new Array(), kt;
	ct = disarm_base64(cipher);
	var result = rijndaelDecrypt(ct, this.key, "CBC");
	
	var header = result.slice(0, 20);
	result = result.slice(20);
	
	/*  Extract the length of the plaintext transmitted and
	    verify its consistency with the length decoded.  Note
	    that in many cases the decrypted messages will include
	    pad bytes added to expand the plaintext to an integral
	    number of AES blocks (blockSizeInBits / 8).  */
	
	var dl = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
    	if ((dl < 0) || (dl > result.length)) {
	    throw "Message (length " + result.length + ") truncated.  " +
	    	dl + " characters expected.";
	    //	Try to sauve qui peut by setting length to entire message
    	    dl = result.length;
	}
	
	/*  Compute MD5 signature of message body and verify
	    against signature in message.  While we're at it,
	    we assemble the plaintext result string.  Note that
	    the length is that just extracted above from the
	    message, *not* the full decrypted message text.
	    AES requires all messages to be an integral number
	    of blocks, and the message may have been padded with
	    zero bytes to fill out the last block; using the
	    length from the message header elides them from
	    both the MD5 computation and plaintext result.  */
	    
	var i, plaintext = "";
	
	md5_init();
	for (i = 0; i < dl; i++) {
	    plaintext += String.fromCharCode(result[i]);
	    md5_update(result[i]);
	}
	md5_finish();

	for (i = 0; i < digestBits.length; i++) {
	    if (digestBits[i] != header[i]) {
	    	throw "Message corrupted.  Checksum of decrypted message does not match.";
		break;
	    }
	}
	
	//  That's it; plug plaintext into the result field
	
	return decode_utf8(plaintext);
    },
    
    //	Retrieve word given index in list of words of that length

    retrieveWord : function(length, index) {
    	if ((length >= minw) && (length <= maxw) &&
	    (index >= 0) && (index < nwords[length])) {
	    return cwords[length].substring(length * index, length * (index + 1));
	}
	return "";
    },
    
    //	Obtain word by index in complete dictionary
    
    indexWord : function(index) {
    	if ((index >= 0) && (index < twords)) {
	    var j;

	    for (j = minw; j <= maxw; j++) {
		if (index < nwords[j]) {
		    break;
		}
		index -= nwords[j];
	    }
	    return this.retrieveWord(j, index);
	}
	return "";
    },
    
    
    //	Hide text as words
    hideText : function(ciphertext) {
	var ct = new Array(), kt, padded = false;
	var purng = new LEcuyer((new Date()).getTime());
	
	ct = disarm_base64(ciphertext);
	
    	/*  Cipher text should always be an even number of bytes.
	    If it isn't, pad it with a zero and set a flag to indicate
	    we've added a pad.  */
	    
	if (ct.length & 1) {
	    ct[ct.length] = 0;
	    padded = true;
	}
	
	/*  Walk through cipher text two bytes at a time,
	    assembling each pair into an index into our table
	    of words.  Append each word to the hidden text.  */
	    
	var i, w, l = "", t = "";
	var maxLine = 72, sl = 0, sc = 0, fpar = false, parl = purng.nextInt(9) + 3, puncture = true;
	    
	for (i = 0; i < ct.length; i += 2) {
	    w = this.indexWord((ct[i] << 8) | ct[i + 1]).toLowerCase();
	    if (puncture && (sl == 0)) {
	    	w = w.substr(0, 1).toUpperCase() + w.substr(1, w.length);
	    }
	    
	    /*	If this is the last word, put a period after it
	    	unless we added a padding byte, in which case we
		end with a bang to so indicate.  */
	
	    if (i == (ct.length - 2)) {
	    	w += padded ? "!" : ".";
    	    } else {	    
	    	if (puncture) {
		
	    	    //  Regular word.  Generate random but plausible punctuation

	    	    sl++;
		    if (sl >= (purng.nextInt(9) + 3)) {
			var p = purng.nextInt(15), pu;
			pu = (p <= 13) ? "." : ((p == 14) ? "?" : "!");
			w += pu + " ";
			sl = 0;
			sc++;
			if (sc >= parl) {
	    		    fpar = true;
			    sc = 0;
			}
		    } else {
			if (purng.nextInt(6) == 6) {
		    	    w += ",";
			}
		    }
		}
	    }
	    if ((l.length + w.length + 1) > maxLine) {
	    	l = l.replace(/\s+$/, "");
	    	t += l + "\n";
		l = "";
	    }
	    if (l.length > 0) {
	    	l += " ";
	    }
	    l += w;
	    if (fpar) {
	    	l = l.replace(/\s+$/, "");
	    	t += l + "\n\n";
		l = "";
		fpar = false;
		parl = purng.nextInt(8) + 2;
	    }
	}
	t += l + "\n";
	
	delete purng;
        return t;
    },
    
    //	Decode text from words
    
    seekText : function(stegotext) {
    	
    	var ct = new Array(), padded = false;
    
    	/*  Precompute table of cumulative words before those
	    of a given length.  */
    	var awords = new Array(), i, j;
	j = 0;
	for (i = minw; i <= maxw; i++) {
	    awords[i] = j;
	    j += nwords[i];
	}
	
    	var t = stegotext, n = 0, v;
	var wpat = /\W*(\w+)\w*/i;
	while (wpat.test(t)) {
	    //	Extract next word from text and determine its length
	    t = t.replace(wpat, "");
	    var w = RegExp.$1;
	    var l = w.length;
	    
	    //	Look it up in the list of words of this length

    	    w = w.substring(0, 1).toUpperCase() +
	    	   w.substring(1, w.length);
	    v = cwords[l].indexOf(w);
	    if (v >= 0) {
	    	v = (v / l) + awords[l];
	    }
    	    if (v == -1) {
                throw "Bogus word "+w;
    	    } else {
		ct[n++] = (v >> 8) & 0xFF;
		ct[n++] = v & 0xFF;
    	    }
	}
	
	if (t.indexOf("!") != -1) {
	    padded = true;
	    ct.pop();
	    n -= 1;
	}
    	v = armour_base64(ct);
	return v;
    }
    
}

jcrypt.init();

var EXPORTED_SYMBOLS = ["jcrypt"];