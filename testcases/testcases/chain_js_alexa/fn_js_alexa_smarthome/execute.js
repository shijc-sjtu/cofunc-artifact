/*
 * Copyright (c) 2020 Institution of Parallel and Distributed System, Shanghai Jiao Tong University
 * ServerlessBench is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 */

const smarthome_handler = require('./smarthome-handler').handler;

// if (process.argv[2] == '--sc-snapshot') {
//     sc.sc_snapshot();
// } else if (process.argv[2] == '--criu-snapshot') {
//     sc.criu_snapshot();
// }

// sc.stat_at_import_done();
// t_import_done = Date.now() / 1000;

async function main(args) {
    var date = new Date();
    const year = date.getFullYear();
    const month = ("0" + (date.getMonth() + 1)).slice(-2);
    const day = ("0" + (date.getDate())).slice(-2);
    const hour = ("0" + (date.getHours())).slice(-2);
    const minute = ("0" + (date.getMinutes())).slice(-2);
    const second = ("0" + (date.getSeconds())).slice(-2);
    const millisecond = ("00" + (date.getMilliseconds())).slice(-3);

    var datestr = "[" + year + "-" + month + "-" + day + "T" + hour + ":" + minute + ":" + second + "." + millisecond + "Z]";


    var response = smarthome_handler.invoke(args);

    // console.log(`RESPONSE++++${JSON.stringify(response)}`);

    return response;
    // .then ( results => {
    //     t_func_done = Date.now() / 1000;
    //     console.log(`t_import_done ${t_import_done}`);
    //     console.log(`t_func_done ${t_func_done}`);
    //     // sc.stat_at_func_done();
    //     results['startTimes'] = {"controllers": results['startTimes'], "smarthome": datestr};
    //     return results;
    // });

  /*  var response = await handler.invoke(args);

    console.log(`RESPONSE++++${JSON.stringify(response)}`);

    response['startTimes'] = {"controllers": response['startTimes'], "smarthome": datestr};
    return response;
*/}

// param = {
//   "context": {
//     "System": {
//       "application": {}
//     }
//   },
//   "request": {
//     "locale": "en-US",
//     "requestId": "amzn1.echo-external.request.b40a87fb-49c3-494b-b965-6df4e46abfac",
//     "timestamp": "2023-10-07T05:47:33Z",
//     "type": "IntentRequest",
//     "intent": {
//       "name": "EnterHomeIntent",
//       "slots": {
//         "password": {
//           "name": "password",
//           "value": "Taylor Swift"
//         }
//       }
//     }
//   },
//   "version": "1.0",
//   "session": {
//     "application": {},
//     "new": true,
//     "sessionId": "SessionID.a49aa2e5-bd98-4941-ae63-586f0b3d583b",
//     "attributes": {}
//   }
// };
handler = main;
fn_name = 'testcases/chain_js_alexa/fn_js_alexa_smarthome';
