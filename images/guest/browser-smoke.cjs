'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');

// Separate exec groups, cleared env, and group cleanup after EVERY command, as in guest.rs.
// AB must setsid its own daemon; merely surviving a shell exit is not sufficient.
function exec(argv) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd: '/home/jail', detached: true,
      env: { HOME: '/home/jail', PATH: '/usr/local/bin:/usr/bin:/bin' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    const killGroup = () => {
      try { process.kill(-child.pid, 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') throw error; }
    };
    const timer = setTimeout(killGroup, 25000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('exit', () => killGroup());
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${argv.join(' ')} exited ${code}: ${output}`));
      else resolve(output);
    });
  });
}

(async () => {
  assert.equal(process.getuid(), 1000);
  const page = title => `data:text/html,${encodeURIComponent(`<title>${title}</title><h1>${title}</h1><button>Local action</button>`)}`;
  try {
    await exec(['browse', 'open', page('Browse smoke')]);
    await exec(['agent-browser', 'open', page('Agent browser smoke')]);
    const snapshot = await exec(['agent-browser', 'snapshot']);
    assert.match(snapshot, /Agent browser smoke/);
    assert.match(snapshot, /Local action/);
    // Both browsers coexist, but neither navigates the other's page.
    assert.match(await exec(['browse', 'snapshot']), /Browse smoke/);
    await exec(['agent-browser', 'close']);
    // Ensure close actually stopped the daemon, not just the client.
    const fs = require('node:fs');
    for (let i = 0; i < 50 && fs.existsSync('/home/jail/.agent-browser/guest.sock'); i++) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(fs.existsSync('/home/jail/.agent-browser/guest.sock'), false);
    console.log('jail browser smoke passed: open/snapshot/close across cleaned exec groups');
  } finally {
    await exec(['agent-browser', 'close']);
    await exec(['browse', 'reset']);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
