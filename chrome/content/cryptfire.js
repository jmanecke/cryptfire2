


var cryptfire  = {
  initialized : false,
  
  include : function(src) {
    var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].getService(Components.interfaces.mozIJSSubScriptLoader);
    loader.loadSubScript("chrome://cryptfire/content/"+src);
  },
  
  onLoad: function() {
      if (this.initialized) return;
        this.initialized = true;

        
        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.stringbundle = this.gfiltersimportexportBundle.createBundle("chrome://cryptfire/locale/overlay.properties");
        var cMenu = document.getElementById("contentAreaContextMenu");
        if (cMenu) {
            cMenu.addEventListener("popupshowing", function () {
                cryptfire.onPopupShowing();
            }, false);
        }
        jcrypt.addEntropy(document);
    },

    getString:function(key) {
        try{
            var str = this.stringbundle.GetStringFromName(key);
            return str;
        }catch(e)
       {
            return key;
       }
    },
    
    encrypt : function() {
        var target = document.popupNode;
        var selection = "";
        if (target) {
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                selection = target.ownerDocument.defaultView.getSelection();
            } else {
                selection = target.value;
                if (target.selectionStart) {
                    selection = selection.substr(target.selectionStart, target.selectionEnd-target.selectionStart);
                }
            }
        } 
        var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                        .getService(Components.interfaces.nsIPromptService);
        var pass = { value : jcrypt.getRememberedPass() };
        var remember = { value : false};
        
        if (pass.value || prompts.promptPassword(window,
                        "Password Dialog",
                        "Enter decryption password or passphrase",
                        pass,
                        "Remember password",
                        remember));
         
        try {
            if (remember.value) {
                jcrypt.rememberPass(pass.value);
            }
            var encrypted = jcrypt.encryptText(selection.toString(), pass.value);
            var gClipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"].getService(Components.interfaces.nsIClipboardHelper);  
            gClipboardHelper.copyString(encrypted);  
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                 alert("Copied encrypted text to Clipboard:\n"+encrypted);
                 
            } else {
                target.value = target.value.substr(0, target.selectionStart) + encrypted + target.value.substr(target.selectionEnd, target.value.length-target.selectionEnd);                
            }            
           
        } catch(E) {
            Components.utils.reportError(E);
            alert("Encryption failed:"+E);
        }
        
    },
    
    forget : function() {
        jcrypt.rememberPass("");
    },
    
    visit : function() {
        gBrowser.selectedTab = gBrowser.addTab("http://cryptfire.com/");
    },
    
    decrypt : function() {
        var target = document.popupNode;
        var selection = "";
        if (target) {
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                selection = target.ownerDocument.defaultView.getSelection();
            } else {
                selection = target.value;
                if (target.selectionStart) {
                    selection = selection.substr(target.selectionStart, target.selectionEnd-target.selectionStart);
                }
            }
        } 
        var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                        .getService(Components.interfaces.nsIPromptService);
        var pass = { value : jcrypt.getRememberedPass() };
        
        var remember = { value : false};
        
        if (pass.value || prompts.promptPassword(window,
                        "Password Dialog",
                        "Enter decryption password or passphrase",
                        pass,
                        "Remember password",
                        remember));
        try {
            if (remember.value) {
                jcrypt.rememberPass(pass.value);
            }
            var decrypted = false;
            try {
                
                decrypted = jcrypt.decryptText(selection.toString(), pass.value);
            } catch(E) {
                decrypted = jcrypt.seekText(selection.toString());
                decrypted = jcrypt.decryptText(decrypted, pass.value);
            }
            var gClipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"].getService(Components.interfaces.nsIClipboardHelper);  
            gClipboardHelper.copyString(decrypted);  
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                 alert("Copied decrypted text to Clipboard:\n"+dencrypted);
            } else {
                target.value = target.value.substr(0, target.selectionStart) + decrypted + target.value.substr(target.selectionEnd, target.value.length-target.selectionEnd);                
            } 
        } catch(E) {
            alert("Decryption failed. Propably the password is wrong, or the text is not encrypted");
        }
        
    },
    
    encryptAsLink : function() {
        var target = document.popupNode;
        var selection = "";
        if (target) {
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                selection = target.ownerDocument.defaultView.getSelection();
            } else {
                selection = target.value;
                if (target.selectionStart) {
                    selection = selection.substr(target.selectionStart, target.selectionEnd-target.selectionStart);
                }
            }
        } 
        var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                        .getService(Components.interfaces.nsIPromptService);
        var pass = { value : jcrypt.getRememberedPass() };
        var remember = { value : false};
        
        if (pass.value || prompts.promptPassword(window,
                        "Password Dialog",
                        "Enter decryption password or passphrase",
                        pass,
                        "Remember password",
                        remember));
         
        try {
            if (remember.value) {
                jcrypt.rememberPass(pass.value);
            }
            var encrypted = jcrypt.encryptText(selection.toString(), pass.value);
            var req = new XMLHttpRequest();  
            req.open('GET', 'http://cryptfire.com/tinyurl.php?url='+encodeURIComponent("http://cryptfire.com/#" + encodeURIComponent(encrypted)), false);   
            req.send(null);  
            if(req.status == 200) { 
                encrypted = req.responseText;  
            } else {
                alert("Creation of link failed. HTTP Status Code "+req.status);
                return;
            }
            var gClipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"].getService(Components.interfaces.nsIClipboardHelper);  
            gClipboardHelper.copyString(encrypted);  
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                 alert("Copied link to Clipboard:\n"+encrypted);
                 
            } else {
                target.value = target.value.substr(0, target.selectionStart) + encrypted + target.value.substr(target.selectionEnd, target.value.length-target.selectionEnd);                
            }            
           
        } catch(E) {
            Components.utils.reportError(E);
            alert("Encryption failed:"+E);
        }
    },
    
    encryptAsText : function() {
        var target = document.popupNode;
        var selection = "";
        if (target) {
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                selection = target.ownerDocument.defaultView.getSelection();
            } else {
                selection = target.value;
                if (target.selectionStart) {
                    selection = selection.substr(target.selectionStart, target.selectionEnd-target.selectionStart);
                }
            }
        } 
        var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                        .getService(Components.interfaces.nsIPromptService);
        var pass = { value : jcrypt.getRememberedPass() };
        var remember = { value : false};
        
        if (pass.value || prompts.promptPassword(window,
                        "Password Dialog",
                        "Enter decryption password or passphrase",
                        pass,
                        "Remember password",
                        remember));
         
        try {
            if (remember.value) {
                jcrypt.rememberPass(pass.value);
            }
            var encrypted = jcrypt.encryptText(selection.toString(), pass.value);
            encrypted = jcrypt.hideText(encrypted);
            var gClipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"].getService(Components.interfaces.nsIClipboardHelper);  
            gClipboardHelper.copyString(encrypted);  
            if (!((target instanceof HTMLInputElement) || (target instanceof HTMLTextAreaElement))) {
                 alert("Copied encrypted text to Clipboard:\n"+encrypted);
                 
            } else {
                target.value = target.value.substr(0, target.selectionStart) + encrypted + target.value.substr(target.selectionEnd, target.value.length-target.selectionEnd);                
            }            
           
        } catch(E) {
            Components.utils.reportError(E);
            alert("Encryption failed:"+E);
        }
        
    },
    
    onPopupShowing : function() {
        
    }
    
};

Components.utils.import("resource://cryptfire/jcrypt_module.js");
window.addEventListener("load", function(e) { cryptfire.onLoad(e); }, false); 

