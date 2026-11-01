#!/bin/sh
set -eu
[ "$(id -u)" = 1000 ]
[ "$(cat /sys/fs/cgroup/memory.max)" = 536870912 ]
[ "$(cat /sys/fs/cgroup/memory.swap.max)" = 0 ]
work=$(mktemp -d /scratch/recordings/memory-smoke.XXXXXX)
trap 'browse reset >/dev/null 2>&1 || true; rm -rf "$work"' EXIT HUP INT TERM
cp /sys/fs/cgroup/memory.events "$work/before"
browse <<'BROWSE'
open 'data:text/html,<title>Selected green tab</title><body style="background:%2311cc33">Selected green tab</body>'
open --tab 'data:text/html,<title>Last purple tab</title><body style="background:%23cc11cc">Last purple tab</body>'
tab 0
BROWSE
browse record bounded
cp /sys/fs/cgroup/memory.events "$work/after"
cp /sys/fs/cgroup/memory.peak "$work/peak"
ffprobe -v error -show_entries stream=codec_name,width,height:format=duration \
    -of json /artifacts/bounded.mp4 > "$work/probe.json"
ffmpeg -v error -threads 1 -i /artifacts/bounded.png -frames:v 1 \
    -pix_fmt rgb24 -threads 1 -f rawvideo "$work/preview.rgb"
ffmpeg -v error -threads 1 -i /artifacts/bounded.mp4 -frames:v 1 \
    -pix_fmt rgb24 -threads 1 -f rawvideo "$work/first.rgb"
python3 - "$work" <<'PY'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
def events(name):
    return dict(line.split() for line in (work / name).read_text().splitlines())
before, after = events('before'), events('after')
kills = int(after['oom_kill']) - int(before['oom_kill'])
assert kills == 0, f'recording caused {kills} cgroup OOM kills'
probe = json.loads((work / 'probe.json').read_text())
assert probe['streams'] == [{'codec_name': 'h264', 'width': 1280, 'height': 720}]
assert abs(float(probe['format']['duration']) - 10) < 0.1
preview = (work / 'preview.rgb').read_bytes()
first = (work / 'first.rgb').read_bytes()
assert len(preview) == len(first) == 1280 * 720 * 3
assert preview[-3:] == bytes([0x11, 0xcc, 0x33]), 'recorded the last tab instead of the selected tab'
assert sum(abs(a - b) for a, b in zip(first, preview)) // len(first) < 12
print(f'512 MiB recording smoke: oom_kill_delta={kills}, memory.peak={(work / "peak").read_text().strip()}, ffprobe={json.dumps(probe)}')
PY
