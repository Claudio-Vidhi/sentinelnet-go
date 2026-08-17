import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const dir = 'web/static/js';
if (!fs.existsSync(dir)) {
  console.error(`Directory ${dir} not found`);
  process.exit(1);
}

let errors = 0;
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));

console.log(`Checking syntax for ${files.length} JavaScript files in ${dir}...`);

for (const file of files) {
  const filePath = path.join(dir, file);
  const code = fs.readFileSync(filePath, 'utf8');
  try {
    new vm.Script(code, { filename: file });
  } catch (err) {
    console.error(`❌ Syntax Error in ${file}:`);
    console.error(`   ${err.message}`);
    if (err.stack) {
      const firstStackLine = err.stack.split('\n')[0];
      console.error(`   ${firstStackLine}`);
    }
    errors++;
  }
}

if (errors > 0) {
  console.error(`\n❌ Found ${errors} syntax error(s) in JavaScript files.`);
  process.exit(1);
} else {
  console.log(`✅ All ${files.length} JavaScript files parsed successfully with zero syntax errors.`);
}
