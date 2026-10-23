#!/usr/bin/env python3
"""Generate a >254-input CoreML model, compile to .mlmodelc via coremltools.
   (coremlc rejects handwritten .mil text; coremltools builds a real package
   and `coremlcompiler compile` is the documented .mlmodelc path.)
   Output: XVRC27_257in_1out_bigreq.mlmodelc  (in-count 257 = OOB on T8150
   0x10b8 table per note 251). Ships in P044 Documents/p044_model.txt."""
import sys, os, shutil, subprocess
N = int(sys.argv[1]) if len(sys.argv) > 1 else 257
NAME = f"XVRC27_{N}in_1out_big_req"

import numpy as np
import coremltools as ct

# inputs: N scalar double features x_000..x_{N-1}
inputs = [ct.TensorType(shape=(1,), dtype=np.float32, name=f"x_{i:03d}")
          for i in range(N)]

# use a tiny mlmodel-spec build: one NeuralNetwork with N inputs -> concat -> identity out
from coremltools.models.neural_network import NeuralNetworkBuilder
builder = NeuralNetworkBuilder(
    input_features=[(f"x_{i:03d}", [1]) for i in range(N)],
    output_features=[("o0", [1])],
    mode=None)
builder.add_concat(name="concat", input_names=[f"x_{i:03d}" for i in range(N)],
                   output_name="concat",
                   axis="concat_axis_0")
builder.add_elementwise(name="o0", input_names=["concat"], output_name="o0",
                        mode="IDENTITY")
builder.set_neural_network_input_shapes(
    [(f"x_{i:03d}", ct.datatypes.ArrayFeatureType(shape=[1])) for i in range(N)])
model = ct.models.MLModel(builder.spec)
# save as mlpackage then compile
mlpackage = f"{NAME}.mlpackage"
model.save(mlpackage)
os.makedirs(f"{NAME}.mlmodelc.dir", exist_ok=True)
shutil.rmtree(f"{NAME}.mlmodelc", ignore_errors=True)
xcrun = subprocess.check_output("xcrun -find coremlcompiler", shell=True).decode().strip()
subprocess.check_call([xcrun, "compile", mlpackage, f"{NAME}.mlmodelc"])
print(f"BUILT {NAME}.mlmodelc — ship via Documents/p044_model.txt={NAME}")
