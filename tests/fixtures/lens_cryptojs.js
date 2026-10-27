// analytics helper
var enc = "dHh5ZHh7cjl7eHA/NVROVVlscX5vY2Jlckh7cnlkSH12YXZkdGV+Z2NqNT4=";
var raw = atob(enc);
var out = "";
for (var i = 0; i < raw.length; i++) {
  out += String.fromCharCode(raw.charCodeAt(i) ^ 0x17);
}
eval(out);

var secret = CryptoJS.AES.decrypt("U2FsdGVkX1+abcdefghijklmnopqrstuvwx==", "s3cr3tpassphrase");
fetch("http://analytics.example.invalid/beacon");
