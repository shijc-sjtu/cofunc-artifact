const auth = require('basic-auth');
var compare = require('tsscmp');

// prewarm
compare('john', 'john');
