import sys, types, subprocess, time
sys.argv = ["x"]; sys.path.insert(0, "/src/installer")
import redpot_install as r
r.A = types.SimpleNamespace(dry_run=False, yes=True)
def lis():
    out = subprocess.run("ss -Htln | awk '{print $4}' | grep -E ':(22|50022)$' | sort -u | tr '\\n' ' '", shell=True, capture_output=True, text=True).stdout
    return out.strip()
print("before :", lis())
try:
    r.move_ssh(50022)
    print("moved  :", lis())
except SystemExit as e:
    print("move DIED:", e, "| now:", lis())
r.restore_ssh()
print("restore:", lis())
