#!/usr/bin/env python3
"""Generate a >254-input CoreML model, compile to .mlmodelc via coremlcompiler.
   (coremlc rejects handwritten .mil; builder helpers drift across
   coremltools versions — so this writes the Model spec protobuf DIRECTLY.
   One Concat layer: x_000..x_{N-1} -> o0. No weights, no validation pass.)
   Output: XVRC27_{N}in_1out_big_req.mlmodelc  (in-count 257 = OOB on T8150
   0x10b8 table per note 251). Ships via Documents/p044_model.txt."""
import sys, os, shutil, subprocess
N = int(sys.argv[1]) if len(sys.argv) > 1 else 257
NAME = f"XVRC27_{N}in_1out_big_req"

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

out = spec.description.output.add()
out.name = "o0"
out.type.multiArrayType.shape.extend([N])
out.type.multiArrayType.dataType = ArrayFeatureType.FLOAT32
spec.description.predictedFeatureName = "o0"

nn = spec.neuralNetwork
concat = nn.layers.add()
concat.name = "concat"
concat.input.extend(names)          # 257 inputs -> single output
concat.output.append("o0")
concat.concatND.axis = 0              # concat axis 0 of the rank-1 arrays
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