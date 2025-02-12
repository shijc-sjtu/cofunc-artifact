const fs = require('fs'),
      path = require('path'),
      request = require('request'),
      storage = require('./storage');

// if (process.argv[2] == '--sc-snapshot') {
//   sc.sc_snapshot();
// } else if (process.argv[2] == '--sc-polling') {
//   sc.start_polling();
// } else if (process.argv[2] == '--criu-snapshot') {
//   sc.criu_snapshot();
// };

// sc.stat_at_import_done();
// t_import_done = Date.now() / 1000;
t_network = 0;

let storage_handler = new storage.storage();

function streamToPromise(stream) {
  return new Promise(function(resolve, reject) {
    stream.on("close", () =>  {
      resolve();
    });
    stream.on("error", reject);
  })
}

handler = async function(event) {
  let output_bucket = event.bucket.output
  let url = event.object.url
  let upload_key = path.basename(url)
  let download_path = path.join('/tmp', upload_key)

  var file = fs.createWriteStream(download_path);
  request(url).pipe(file);
  let promise = streamToPromise(file);
  var keyName;
  let upload = promise.then(
    async () => {
      [keyName, promise] = storage_handler.upload(output_bucket, upload_key, download_path);
      await promise;
    }
  );

  t0 = Date.now() / 1000;
  await upload;
  t1 = Date.now() / 1000;
  t_network += t1 - t0;
  
  return {bucket: output_bucket, url: url, key: keyName}
};

// param = {
//   'bucket': {
//     'output': 'output',
//   },
//   'object': {
//     'url': 'http://127.0.0.1:8080/1.4.0.zip',
//   },
// }

// handler({
//   'bucket': {
//     'output': 'output',
//   },
//   'object': {
//     'url': 'http://127.0.0.1:8080/1.4.0.zip',
//   },
// }).then(() => {
//   t_func_done = Date.now() / 1000;
//   console.log(`t_import_done ${t_import_done}`);
//   console.log(`t_func_done ${t_func_done}`);
//   sc.stat_at_func_done();
// })

fn_name = 'testcases/fn_js_uploader';
