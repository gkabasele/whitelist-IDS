import shutil
import os
import medium_process
import threading
import argparse
import subprocess
import plc_generator
import logging
from constants import *


logging.basicConfig(filename = LOG, mode = 'w', format='[%(asctime)s][%(levelname)s][%(pathname)s-%(lineno)d] %(message)s', level = logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument("--create", dest="create_dir", action="store_true", help="Create export directory for variable processes")
parser.add_argument("--nb", dest="nb_round", type=int, default=5, action="store", help="Number of iteration for the process execution") 
args = parser.parse_args()

if os.path.exists(STORE):
    shutil.rmtree(STORE)

if os.path.exists(PLCS_DIR):
    shutil.rmtree(PLCS_DIR)

if args.create_dir:
    if os.path.exists(EXPORT_VAR):
        shutil.rmtree(EXPORT_VAR)
    os.mkdir(EXPORT_VAR)

os.mkdir(STORE)
os.mkdir(PLCS_DIR)

plc_generator.create_plc_scripts()

t = threading.Thread(name='process', target=medium_process.start, args=(STORE, args.nb_round))
t.start()


processes = {}
processes_output = {}
cre = "--create" if args.create_dir else ""

for port,filename in enumerate(os.listdir(PLCS_DIR), 0):
    if filename.endswith(".py"):
        proc = subprocess.Popen(["python", PLCS_DIR+"/"+filename, "--ip", "localhost", "--port", str(5020+port), "--store", STORE, "--duration", str(DURATION), "--export", EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes[filename] = proc

mtu_proc = subprocess.Popen(["python", "script_mtu.py", "--ip", "localhost", "--port", str(3000), "--duration", str(DURATION) , "--import", EXPORT_VAR], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(mtu_out, mtu_err) = mtu_proc.communicate()

for k,v in processes.iteritems():
    (proc_out, proc_err) = v.communicate()
    processes_output[k] = (proc_out, proc_err)
    print proc_out
    print proc_err
    v.wait()

print mtu_err
mtu_proc.wait()
t.join()

