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

'use strict';

const express = require('express');
const bodyParser = require('body-parser')
const fs = require('fs');

// Constants
const PORT = 8888;
const HOST = '0.0.0.0';

// Control variables
var dev_switch = 'OFF';

// App
const app = express();
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

app.post('/get_param', (req, res) => {
  var fn_name = req.body['fn_name'];
  res.send(fs.readFileSync(`/testcases/${fn_name}/param.json`));
});

app.post('/set_retval', (req, res) => {
    // console.log(req.body);
    res.send('OK');
})

app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);
