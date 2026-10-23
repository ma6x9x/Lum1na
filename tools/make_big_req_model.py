#!/usr/bin/env python3
"""Generate a >254-input CoreML model, compile to .mlmodelc via coremlcompiler.
   (coremlc rejects handwritten .mil; builder helpers drift across
   coremltools versions — so this writes the Model spec protobuf DIRECTLY.
   One Concat layer: x_000..x_{N-1} -> o0. No weights, no validation pass.)
   Output: XVRC27_{N}in_1out_big_req.mlmodelc  (in-count 257 = OOB on T8150
   0x10b8 table per note 251). Ships via Documents/p044_model.txt."""
import sys, os, shutil, subprocess
N = int(sys.argv[1]) if len(sys.argv) > 1 else 257
K = int(sys.argv[2]) if len(sys.argv) > 2 else 1  # outputs
NAME = f"XVRC27_{N}in_{K}out_big_req"

from coremltools.proto import Model_pb2
from coremltools.proto.NeuralNetwork_pb2 import (
    ArrayFeatureType, ConcatNDLayerParams)

spec = Model_pb2.Model()
spec.specificationVersion = 7  # spec-7 = P044's version on-device

names = [f"x_{i:03d}" for i in range(N)]
for n in names:
    f = spec.description.input.add()
    f.name = n
    f.type.multiArrayType.shape.extend([1])
    f.type.multiArrayType.dataType = ArrayFeatureType.FLOAT32

for k in range(K):
    out = spec.description.output.add()
    out.name = f"o{k}" if K > 1 else "o0"
    out.type.multiArrayType.shape.extend([N])
    out.type.multiArrayType.dataType = ArrayFeatureType.FLOAT32
spec.description.predictedFeatureName = "o0"

nn = spec.neuralNetwork
concat = nn.layers.add()
concat.name = "concat"
concat.input.extend(names)          # 257 inputs -> single output
concat.output.append("o0")
concat.concatND.axis = 0              # concat axis 0 of the rank-1 arrays
# K-1 identity outputs: concatND of ONE input (records = inputs + K)
for k in range(1, K):
    # identity outputs are copies of ONE scalar -> shape [1] (CoreML
    # validates declared shape vs actual; record count is FEATURES, not bytes)
    odesc = spec.description.output[k]
    del odesc.type.multiArrayType.shape[:]
    odesc.type.multiArrayType.shape.extend([1])
    lay = nn.layers.add()
    lay.name = f"id_{k}"
    lay.input.append(names[N - k])
    lay.output.append(f"o{k}")
    lay.copy.SetInParent()  # presence marks the layer as type copy (no params)

nn.arrayInputShapeMapping = 1        # EXACT_ARRAY_MAPPING (required for spec-v7 layers)

mlmodel = f"{NAME}.mlmodel"
with open(mlmodel, "wb") as fp:
    fp.write(spec.SerializeToString())
print(f"wrote {mlmodel} ({os.path.getsize(mlmodel)} bytes), spec v7, {N} inputs")

xc = os.environ.get("COREMLCOMPILER")
if not xc:
    xc = subprocess.check_output("xcrun -find coremlcompiler", shell=True).decode().strip()
shutil.rmtree(f"/tmp/{NAME}.mlmodelc", ignore_errors=True)
subprocess.check_call([xc, "compile", mlmodel, f"/tmp/{NAME}.mlmodelc"])
print(f"BUILT /tmp/{NAME}.mlmodelc — ship via Documents/p044_model.txt={NAME}")