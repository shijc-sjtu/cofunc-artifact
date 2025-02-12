const auth = require('basic-auth');
var compare = require('tsscmp');

handler = async function(param) {
    compare(param['name'], 'john');
    compare(param['pass'], 'secret');
}

fn_name = 'testcases/fn_js_dynamic_html';
