const jsObfuscator = require('javascript-obfuscator');
const fs = require('fs');

var code = '',
    kvkit_lines = fs.readFileSync(__dirname + '/kvkit.js').toString().split('\n'),
    helpers_lines = fs.readFileSync(__dirname + '/kvkit_helpers.js').toString().split('\n'),
    requirements = {};

for(let line of kvkit_lines) {
    if(line.includes("= require('")) {
        let split_line = line.split(' = ');
        let varName = split_line[0].replace('const ','');
        let requireStatement = split_line[1];

        requirements[varName] = requireStatement;
    }
}

for(let line of helpers_lines) {
    if(line.includes("= require('")) {
        let split_line = line.split(' = ');
        let varName = split_line[0].replace('const ','');
        let requireStatement = split_line[1];

        requirements[varName] = requireStatement;
    }
}

delete requirements['kvkit'];
for(let requirement in requirements) {
    code += `const ${requirement} = ${requirements[requirement]}\n`;
}

for(let line of helpers_lines) {
    if(!line.includes("= require('")) {
        code += line + '\n';
    }
}

for(let line of kvkit_lines) {
    if(!line.includes("= require('")) {
        code += line + '\n';
    }
}

code = code.replace('module.exports = kvkit;','');

var obfuscator = jsObfuscator.obfuscate(code,{
    compact:true,
    simplify:true,
    controlFlowFlattening:true,
    controlFlowFlatteningThreshold:1,
    numbersToExpressions:true,
    stringArray:true,
    shuffleStringArray:true,
    rotateStringArray:true,
    stringArrayEncoding:['base64','rc4'],
    splitStrings:true,
    stringArrayThreshold:1
});

fs.writeFileSync(__dirname + '/kvkit-bin.js',obfuscator.getObfuscatedCode());