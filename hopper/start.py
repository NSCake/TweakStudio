import subprocess
import time
from pathlib import Path
from hopper_proxy import TerminateHopper

TerminateHopper.kill_hopper()

testbin_path = Path("lzssdec").resolve()
proxy_script_path = Path("hopper_proxy.py").resolve()
hopper_path = "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper"

# Launch Hopper with a test binary and the proxy script
# Work around the "missing loader" bug
for _ in range(2):
    try:
        subprocess.check_output([hopper_path, "-e", testbin_path, "-l", "Mach-O", "--aarch64", "-Y", proxy_script_path.as_posix()], stderr=subprocess.STDOUT)
        break
    except subprocess.CalledProcessError as e:
        if e.stdout and b"The handler some object is not defined." in e.stdout:
            # Workaround the bug
            try:
                subprocess.check_output([hopper_path], stderr=subprocess.STDOUT)
            except:
                pass
            time.sleep(1)
        else:
            print(e.stdout)
            raise
