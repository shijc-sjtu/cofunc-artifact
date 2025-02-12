const Mustache = require('mustache');
const fs = require('fs');
const net = require('./net')
const sc = require('/lib/sc_js_binding');

// if (process.argv[2] == '--sc-snapshot') {
//   sc.sc_snapshot();
// } else if (process.argv[2] == '--criu-snapshot') {
//   sc.criu_snapshot();
// }

// sc.stat_at_import_done();
t_import_done = Date.now() / 1000;

function random(b, e) {
  return Math.round(Math.random() * (e - b) + b);
}

handler = async function(event) {
  var random_numbers = new Array(event.random_len);
  for(var i = 0; i < event.random_len; ++i) {
    random_numbers[i] = random(0, 100);
  }
  var input = {
    cur_time: new Date().toLocaleString(),
    username: event.username,
    random_numbers: random_numbers
  };

  return new Promise((resolve, reject) => {
    fs.readFile('/func/template.html', "utf-8",
      function(err, data) {
        if(err) reject(err);
        resolve(Mustache.render(data, input));
      }
    );
  });
};

// param = {
//   'random_len': 1000,
//   'username': 'user',
// };
fn_name = 'testcases/fn_js_dynamic_html';
// handler({
//   'random_len': 1000,
//   'username': 'user',
// }).then(() => {
//   t_func_done = Date.now() / 1000;
//   console.log(`t_import_done ${t_import_done}`);
//   console.log(`t_func_done ${t_func_done}`);
//   // sc.stat_at_func_done();
// })
