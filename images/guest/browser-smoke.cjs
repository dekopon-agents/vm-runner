'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');

// Separate exec groups, cleared env, and group cleanup after EVERY command, as in guest.rs.
// AB must setsid its own daemon; merely surviving a shell exit is not sufficient.
function exec(argv, expectedCode = 0) {
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
      if (code !== expectedCode) reject(new Error(`${argv.join(' ')} exited ${code}, expected ${expectedCode}: ${output}`));
      else resolve(output);
    });
  });
}

(async () => {
  assert.equal(process.getuid(), 1000);
  const page = title => `data:text/html,${encodeURIComponent(`<title>${title}</title><h1>${title}</h1><button>Local action</button>`)}`;
  try {
    await exec(['browse', 'open', page('Browse smoke')]);
    const artifacts = fs.readdirSync('/artifacts');
    const recordings = fs.readdirSync('/scratch/recordings');
    for (const [command, code] of [[['browse', 'record'], 1], [['record-cdp'], 2]]) {
      for (const name of ['', '../escape', '-bad', '_bad', 'bad name', 'bad.mp4', 'é', 'a'.repeat(125)]) {
        assert.match(await exec([...command, name], code), /record NAME|usage: record-cdp/);
      }
      for (const seconds of ['0', '31', '-1', '1.5', 'NaN', '']) {
        assert.match(await exec([...command, 'refused', '--seconds', seconds], code), /--seconds/);
      }
      assert.match(await exec([...command, 'refused', '--seconds'], code), /--seconds/);
      assert.match(await exec([...command, 'refused', 'extra'], code), /usage:/);
    }
    assert.deepEqual(fs.readdirSync('/scratch/recordings'), recordings);
    assert.deepEqual(fs.readdirSync('/artifacts'), artifacts);
    assert.equal(await exec(['browse', 'eval', "typeof window.recordTimer === 'undefined'"]), 'true\n');
    const failedCapture = await exec(['sh', '-c', `
      record-cdp --seconds 1 capture-failed &
      recorder=$!
      while :; do
        for work in /scratch/recordings/.record.*; do
          if [ -d "$work" ]; then break 2; fi
        done
        sleep 0.05
      done
      mkdir "$work/frame00.png"
      code=0
      wait "$recorder" || code=$?
      test "$code" -eq 1
    `]);
    assert.match(failedCapture, /EISDIR/);
    assert.equal(await exec(['browse', 'eval', "typeof window.recordTimer === 'number' && document.querySelector('[data-cdp-recording]') === null"]), 'true\n');
    assert.deepEqual(fs.readdirSync('/scratch/recordings'), recordings);
    assert.deepEqual(fs.readdirSync('/artifacts'), artifacts);
    console.log('record refuses invalid names and seconds before capture and cleans up a failed capture');
    await exec(['browse', 'open', 'data:text/html,<p>smoke</p>']);
    await exec(['browse', 'record', 'smoke', '--seconds', '3']);
    const probe = JSON.parse(await exec(['ffprobe', '-v', 'error', '-show_entries',
      'stream=codec_name,width,height:format=duration', '-of', 'json', '/artifacts/smoke.mp4']));
    assert.deepEqual(probe.streams, [{ codec_name: 'h264', width: 1280, height: 720 }]);
    assert.ok(Math.abs(Number(probe.format.duration) - 3) < 0.1);
    assert.ok(fs.statSync('/artifacts/smoke.png').size > 0);
    console.log(`producer/consumer smoke ffprobe=${JSON.stringify(probe)}`);
    fs.unlinkSync('/artifacts/smoke.mp4');
    fs.unlinkSync('/artifacts/smoke.png');
    await exec(['browse', 'open', page('Browse smoke')]);
    await exec(['agent-browser', 'open', page('Agent browser smoke')]);
    const snapshot = await exec(['agent-browser', 'snapshot']);
    assert.match(snapshot, /Agent browser smoke/);
    assert.match(snapshot, /Local action/);
    // Both browsers coexist, but neither navigates the other's page.
    assert.match(await exec(['browse', 'snapshot']), /Browse smoke/);
    await exec(['agent-browser', 'close']);
    // Ensure close actually stopped the daemon, not just the client.
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
