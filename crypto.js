'use strict';
const crypto = require('crypto');
const param = crypto.randomBytes(8).toString('hex');

console.log(param);