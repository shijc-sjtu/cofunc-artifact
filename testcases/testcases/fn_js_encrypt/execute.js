// AES 128 encryption

const crypto = require('crypto');
// const fs = require('fs');
const storage = require('./storage');
// const sc = require('/lib/sc_js_binding');

// if (process.argv[2] == '--sc-snapshot') {
//   sc.sc_snapshot();
// } else if (process.argv[2] == '--criu-snapshot') {
//   sc.criu_snapshot();
// }

// sc.stat_at_import_done();
t_import_done = Date.now() / 1000;

let storage_handler = new storage.storage();

input_bucket = 'input';
output_bucket = 'output';
key = 'sample.txt';
upload_key = 'sample.out.txt';

// input file
// const r = fs.createReadStream('/func/sample.txt');
let read_promise = storage_handler.downloadStream(input_bucket, key);

const algorithm = 'aes-256-ctr';
const secretKey = 'vOVH6sdmpNWjRRIqCc7rdxs01lwHzfr3';
const iv = crypto.randomBytes(16);

// encrypt content
const encrypt = crypto.createCipheriv(algorithm, secretKey, iv);

// decrypt content
const decrypt = crypto.createDecipheriv(algorithm, secretKey, iv);

// write file
// const w = fs.createWriteStream('/func/sample.out.txt');
let [writeStream, promise, uploadName] = storage_handler.uploadStream(output_bucket, upload_key);

// Basic function to encrypt/decrypt a stream for example
async function enc_file() {

	// start pipe
	// return r.pipe(encrypt)
	// 	.pipe(decrypt)
	// 	.pipe(w);
  read_promise.then(
    (input_stream) => {
      input_stream.pipe(encrypt).pipe(decrypt).pipe(writeStream);
    }
  );
  await promise;
}

// param = null;
handler = enc_file;
fn_name = 'testcases/fn_js_encrypt';

// enc_file().then(() => {
//   t_func_done = Date.now() / 1000;
//   console.log(`t_import_done ${t_import_done}`);
//   console.log(`t_func_done ${t_func_done}`);
//   // sc.stat_at_func_done();
// })
