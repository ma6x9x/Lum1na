#!/usr/bin/env python3
"""Emit XVRC27_254in_passthrough — 254 identity x_i → y_i, no addchain.

HOLD: P044 still fires XVRC27_254in_1out_addchain. Do not swap COREML_MODEL_NAME
until v45 prints guardfat MUTATED / FAT OOL MUTATED.

Inputs match createFeatures (x_000..x_253, Double [1]). Each input is wired
so CoreML cannot DCE it (254 IOSurfaces / CheckandPrewire overflow).
Do not drop the .mlmodel into the Xcode sync folder — coremlc breaks the IPA.
Ship the precompiled .mlmodelc only.

  python3 tools/make_254_passthrough.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

N = 254
ROOT = Path(__file__).resolve().parents[1]
OUT_MLC = ROOT / "model" / "XVRC27_254in_passthrough.mlmodelc"
TMP_MLMODEL = Path("/tmp/XVRC27_254in_passthrough.mlmodel")
TMP_COMPILE = Path("/tmp/xvrc27_passthrough_mlc")


def build_spec():
    from coremltools.models.datatypes import Array
    from coremltools.models.neural_network import NeuralNetworkBuilder
    from coremltools.proto import FeatureTypes_pb2 as ft

    inputs = [(f"x_{i:03d}", Array(1)) for i in range(N)]
    outputs = [(f"y_{i:03d}", Array(1)) for i in range(N)]
    builder = NeuralNetworkBuilder(
        input_features=inputs,
        output_features=outputs,
        disable_rank5_shape_mapping=True,
    )
    for i in range(N):
        builder.add_elementwise(
            name=f"id_{i:03d}",
            input_names=[f"x_{i:03d}"],
            output_name=f"y_{i:03d}",
            mode="MULTIPLY",
            alpha=1.0,
        )
    spec = builder.spec
    for t in list(spec.description.input) + list(spec.description.output):
        t.type.multiArrayType.dataType = ft.ArrayFeatureType.DOUBLE
    spec.description.metadata.shortDescription = (
        "XVRC-27 254-in passthrough: y_i = x_i. HOLD until P044 v45 conversion."
    )
    spec.description.metadata.author = "Lum1na passthrough generator"
    spec.specificationVersion = max(spec.specificationVersion, 4)
    return spec


def find_coremlc() -> Path | None:
    for root in (
        Path("/Users/kolby/Downloads/Xcode.app/Contents/Developer"),
        Path("/Applications/Xcode.app/Contents/Developer"),
    ):
        cand = root / "usr" / "bin" / "coremlc"
        if cand.is_file():
            return cand
    which = shutil.which("coremlc")
    return Path(which) if which else None


def main() -> int:
    spec = build_spec()
    names_in = [t.name for t in spec.description.input]
    names_out = [t.name for t in spec.description.output]
    assert names_in[0] == "x_000" and names_in[-1] == "x_253"
    assert names_out[0] == "y_000" and names_out[-1] == "y_253"
    assert len(names_in) == N and len(names_out) == N
    TMP_MLMODEL.write_bytes(spec.SerializeToString())
    print("wrote", TMP_MLMODEL, "bytes", TMP_MLMODEL.stat().st_size)

    coremlc = find_coremlc()
    if not coremlc:
        print("no coremlc — left", TMP_MLMODEL, file=sys.stderr)
        return 2

    if TMP_COMPILE.exists():
        shutil.rmtree(TMP_COMPILE)
    TMP_COMPILE.mkdir(parents=True)
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    dev = coremlc.parents[2]  # .../Developer
    env["DEVELOPER_DIR"] = str(dev)
    r = subprocess.run(
        [str(coremlc), "compile", str(TMP_MLMODEL), str(TMP_COMPILE)],
        env=env,
        capture_output=True,
        text=True,
    )
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        return r.returncode

    compiled = TMP_COMPILE / "XVRC27_254in_passthrough.mlmodelc"
    if not compiled.is_dir():
        found = list(TMP_COMPILE.glob("*.mlmodelc"))
        if not found:
            print("coremlc produced no mlmodelc under", TMP_COMPILE, file=sys.stderr)
            return 3
        compiled = found[0]
    if OUT_MLC.exists():
        shutil.rmtree(OUT_MLC)
    shutil.copytree(compiled, OUT_MLC)
    print("shipped", OUT_MLC)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
