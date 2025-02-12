const sharp = require('sharp'),
      storage = require('./storage');

// if (process.argv[2] == '--sc-snapshot') {
//   sc.sc_snapshot();
// } else if (process.argv[2] == '--criu-snapshot') {
//   sc.criu_snapshot();
// }

// sc.stat_at_import_done();
// t_import_done = Date.now() / 1000;

sharp.concurrency(1)

let storage_handler = new storage.storage();

handler = async function(event) {
  input_bucket = event.bucket.input
  output_bucket = event.bucket.output
  let key = event.object.key
  width = event.object.width
  height = event.object.height
  let pos = key.lastIndexOf('.');
  let upload_key = key.substr(0, pos < 0 ? key.length : pos) + '.png';

  const sharp_resizer = sharp().resize(width, height).png();
  let read_promise = storage_handler.downloadStream(input_bucket, key);
  let [writeStream, promise, uploadName] = storage_handler.uploadStream(output_bucket, upload_key);
  read_promise.then(
    (input_stream) => {
      input_stream.pipe(sharp_resizer).pipe(writeStream);
    }
  );
  await promise;
  return {bucket: output_bucket, key: uploadName}
};

// param = {
//   'bucket': {
//     'input': 'input',
//     'output': 'output',
//   },
//   'object': {
//     'key': 'sample.jpg',
//     'width': 200,
//     'height': 200,
//   },
// }

// handler({
//   'bucket': {
//     'input': 'input',
//     'output': 'output',
//   },
//   'object': {
//     'key': 'sample.jpg',
//     'width': 200,
//     'height': 200,
//   },
// }).then(() => {
//   t_func_done = Date.now() / 1000;
//   console.log(`t_import_done ${t_import_done}`);
//   console.log(`t_func_done ${t_func_done}`);
//   // sc.stat_at_func_done();
// })

fn_name = 'testcases/fn_js_thumbnailer';
