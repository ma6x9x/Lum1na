#!/usr/bin/env python3
"""Generate a >254-input CoreML model + compile via coremlc (needs Xcode).
   Output: XVRC27_257in_1out_bigreq.mlmodelc  (in-count 257 = 2-record OOB on
   T8150 0x10b8 table per note 251). Ships in P044 Documents/p044_model.txt."""
import os, subprocess, sys, shutil
N = int(sys.argv[1]) if len(sys.argv) > 1 else 257
NAME = f"XVRC27_{N}in_1out_bigreq"
d = NAME
os.makedirs(d, exist_ok=True)
spec = f'''featureType {{ input: [i0..i{N-1}: tensor(1,1,1,1)] output: [o0] }}
network {{
  layer concat: (i0..i{N-1}) -> concat
  layer unary: concat -> o0 {{ op: IDENTITY }}
}}'''
open(f"{d}/model.mil", "w").write(spec)
open(f"{d}/coremldata.spec", "w").write("model-type: neuralNetwork\n")
xcode = "/Applications/Xcode_16.4.app/Contents/Developer"
coremlc = subprocess.check_output(
    f"xcrun -find coremlc", shell=True).decode().strip()
# coremlc arg order differs by version: try both, need --platform too.
import itertools
attempts = [
    [coremlc, "generate", "mlmodelc", f"{d}/model.mil", "-o", f"{d}.mlmodelc",
     "--platform", "iOS", "--deployment-target", "17.0"],
    [coremlc, "generate", f"{d}/model.mil", "mlmodelc", "-o", f"{d}.mlmodelc",
     "--platform", "iOS", "--deployment-target", "17.0"],
]
last = None
for cmd in attempts:
    try:
        subprocess.check_call(cmd); break
    except subprocess.CalledProcessError as e:
        last = e
else:
    raise last
print(f"BUILT {d}.mlmodelc — ship via Documents/p044_model.txt={NAME}")
