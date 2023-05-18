const crypto = require("crypto");
const { readFileSync, writeFileSync } = require('fs');
const { resolve } = require('path');

const uid = () => {
    const id = crypto.randomBytes(16).toString("hex");
    return id
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256');
    hash.update(password + salt);
    const hashedPassword = hash.digest('hex');
    return salt + ':' + hashedPassword;
}

function checkPassword(password, storedPassword) {
    const [salt, hashedPassword] = storedPassword.split(':');
    const hash = crypto.createHash('sha256');
    hash.update(password + salt);
    const hashedInputPassword = hash.digest('hex');
    return hashedInputPassword === hashedPassword;
}

function encode(id) {
    const str = id;
    const buff = Buffer.from(str, 'utf-8');
    const base64 = buff.toString('base64');
    return base64
}

function decode(id) {
    const base64 = id;
    const buff = Buffer.from(base64, 'base64');
    const str = buff.toString('utf-8');
    return str;
}

function read(fileName) {
    let data = readFileSync(resolve('database', fileName + '.json'), 'utf-8')
    return JSON.parse(data)
}


function write(fileName, data) {
    writeFileSync(resolve('database', fileName + '.json'), JSON.stringify(data, null, 4))
    return true
}

module.exports = {
    uid,
    hashPassword,
    checkPassword,
    encode,
    decode,
    read,
    write
}