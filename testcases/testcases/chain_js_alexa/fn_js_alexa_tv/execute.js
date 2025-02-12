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

const tv_handler = require('./tv-handler').handler;

// if (process.argv[2] == '--sc-snapshot') {
//     sc.sc_snapshot();
// } else if (process.argv[2] == '--criu-snapshot') {
//     sc.criu_snapshot();
// }

// sc.stat_at_import_done();
// t_import_done = Date.now() / 1000;

function main(args) {
    var date = new Date();
    const year = date.getFullYear();
    const month = ("0" + (date.getMonth() + 1)).slice(-2);
    const day = ("0" + (date.getDate())).slice(-2);
    const hour = ("0" + (date.getHours())).slice(-2);
    const minute = ("0" + (date.getMinutes())).slice(-2);
    const second = ("0" + (date.getSeconds())).slice(-2);
    const millisecond = ("00" + (date.getMilliseconds())).slice(-3);

    var datestr = "[" + year + "-" + month + "-" + day + "T" + hour + ":" + minute + ":" + second + "." + millisecond + "Z]";

    var response = tv_handler.invoke(args);

    // console.log(`RESPONSE++++${JSON.stringify(response)}`);

    return response;
    // .then ( results => {
    //     t_func_done = Date.now() / 1000;
    //     console.log(`t_import_done ${t_import_done}`);
    //     console.log(`t_func_done ${t_func_done}`);
    //     // sc.stat_at_func_done();
    //     results['startTimes'] = {"tv-controller": datestr};
    //     return results;
    // });
}

// param = {
//     context: { System: { application: {} } },
//     IP: "127.0.0.1",
//     PORT: 9090,
//     request: {
//         locale: 'en-US',
//         requestId: 'amzn1.echo-external.request.86758e10-78e5-4407-85e3-fffeb85ca629',
//         timestamp: '2023-11-10T07:16:00Z',
//         type: 'LaunchRequest'
//     },
//     version: '1.0',
//     session: {
//         application: { applicationId: undefined },
//         new: true,
//         sessionId: 'SessionID.74ad8dcb-d488-4ac0-9bcf-7899bc785c6a'
//     }
// };
handler = main;
fn_name = 'testcases/chain_js_alexa/fn_js_alexa_tv';
