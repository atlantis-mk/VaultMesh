#!/usr/bin/env python3
"""Run AT-DEVICE-ASSIST-001's synthetic locked Android ↔ desktop native transport slice on one device."""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', help='adb device serial; otherwise adb must have exactly one device')
    parser.add_argument('--origin', choices=['https://synthetic.example', 'http://synthetic.example', 'http://localhost:4173'],
                        default='https://synthetic.example', help='Synthetic browser origin bound to the native request')
    parser.add_argument('--push', action='store_true', help='Verify passive reception followed by local fill with phone service stopped')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    adb_path = str(Path(sdk) / 'platform-tools' / ('adb.exe' if os.name == 'nt' else 'adb')) if sdk else shutil.which('adb')
    if not adb_path:
        parser.error('Set ANDROID_HOME or add adb to PATH')
    adb = [adb_path] + (['-s', args.serial] if args.serial else [])
    subprocess.run(adb + ['get-state'], check=True)
    for apk in ['debug/app-debug.apk', 'androidTest/debug/app-debug-androidTest.apk']:
        subprocess.run(adb + ['install', '-r', str(root / 'apps/android/app/build/outputs/apk' / apk)], check=True)
    directory = Path(tempfile.mkdtemp(prefix='vaultmesh-assist-device-'))
    print(f'Synthetic fixture and test logs: {directory}', flush=True)
    device = None
    with (directory / 'host.log').open('w') as host_log, (directory / 'device.log').open('w') as device_log:
        host = subprocess.Popen(['cargo', 'test', '-p', 'vaultmesh-android-runtime',
                                 'desktop_companion_for_android_assist_instrumentation', '--', '--ignored', '--nocapture'],
                                cwd=root, env={**os.environ, 'VM_ASSIST_TEST_DIR': str(directory), 'VM_ASSIST_TEST_ORIGIN': args.origin, 'VM_ASSIST_TEST_PUSH': '1' if args.push else '0'},
                                stdout=host_log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 90
            while not (directory / 'pairing.json').exists():
                if host.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Desktop companion did not start; inspect host.log')
                time.sleep(.1)
            pairing = json.loads((directory / 'pairing.json').read_text())
            # These are short-lived synthetic pairing values, never product credentials.
            device = subprocess.Popen(adb + ['shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
                'com.vaultmesh.app.DeviceAssistInstrumentedTest', '-e', 'syncPeer', pairing['peer'],
                '-e', 'syncCode', pairing['code'], '-e', 'assistPush', str(args.push).lower(),
                'com.vaultmesh.app.debug.test/androidx.test.runner.AndroidJUnitRunner'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            lines = queue.Queue()
            def read_lines():
                for line in device.stdout:
                    lines.put(line)
                lines.put(None)
            threading.Thread(target=read_lines, daemon=True).start()
            deadline = time.monotonic() + 120
            passed = False
            while True:
                if time.monotonic() > deadline:
                    raise RuntimeError('Android test timed out; inspect device.log')
                try:
                    line = lines.get(timeout=.2)
                except queue.Empty:
                    continue
                if line is None:
                    break
                device_log.write(line)
                device_log.flush()
                if 'syncStage=locked' in line:
                    (directory / 'locked').touch()
                if 'syncStage=offline' in line:
                    (directory / 'offline').touch()
                if 'OK (1 test)' in line:
                    passed = True
            device.wait(timeout=5)
            (directory / 'stop').touch()
            host.wait(timeout=15)
            if not passed or device.returncode != 0 or host.returncode != 0 or not (directory / 'success').exists():
                raise RuntimeError('Sync regression failed; inspect host.log and device.log')
            print(f'PASS: {args.origin}: {"passive push then offline local phone/SMS" if args.push else "locked native phone and manual SMS"}; no carrier SMS or browser claim')
        finally:
            (directory / 'stop').touch()
            for process in [device, host]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == '__main__':
    main()
