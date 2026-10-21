#!/usr/bin/env python3
"""Emit XVRC27_192in_1out_addchain — 192 in -> 1 out.

WHY 192 (tonight's decode, round 2 / note-250): the kernel's
InitialChecksAndLookups gate rejects any request whose INPUT count != the
compiled procedure's expectation ("inputs passed (192) does not match
expected (254) for procedure net"). Every over-capacity OOB fill therefore
NEEDS a model whose procedure-inputs == the request inputs:
  request 192 in + 1 out = 193 records vs table capacity 192
  = the LEGIT-count 1-record OOB (v73's designed shape, never yet fired).
Do not bundle a .mlmodel (coremlc breaks the IPA) — ship precompiled .mlmodelc.

  python3 tools/make_192in_addchain.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

N = 192
ROOT = Path(__file__).resolve().parents[1]
OUT_MLC = ROOT / "P007OpenOnly" / "P007OpenOnly" / f"XVRC27_{N}in_1out_addchain.mlmodelc"
TMP_MLMODEL = Path(f"/tmp/XVRC27_{N}in_1out_addchain.mlmodel")
TMP_COMPILE = Path("/tmp/xvrc27_192in_mlc")


def build_spec():
    from coremltools.models.datatypes import Array
    from coremltools.models.neural_network import NeuralNetworkBuilder
    from coremltools.proto import FeatureTypes_pb2 as ft

    inputs = [(f"x_{i:03d}", Array(1)) for i in range(N)]
    builder = NeuralNetworkBuilder(
        input_features=inputs,
        output_features=[("y_add", Array(1))],
        disable_rank5_shape_mapping=True,
    )
    # addchain: running sum via MULTIPLY(1.0) + chained INNER_PRODUCT-style
    # elementwise adds, matching the 254in addchain family's shape.
    builder.add_elementwise(
        name="acc_000",
        input_names=["x_000"],
        output_name="acc_000",
        mode="MULTIPLY",
        alpha=1.0,
    )
    for i in range(1, N):
        builder.add_elementwise(
            name=f"acc_{i:03d}",
            input_names=[f"acc_{i-1:03d}", f"x_{i:03d}"],
            output_name=f"acc_{i:03d}",
            mode="ADD",
        )
    builder.add_elementwise(
        name="out_scale",
        input_names=[f"acc_{N-1:03d}"],
        output_name="y_add",
        mode="MULTIPLY",
        alpha=1.0,
    )
    spec = builder.spec
    for t in spec.description.input:
        t.type.multiArrayType.dataType = ft.ArrayFeatureType.DOUBLE
    spec.description.output[0].type.multiArrayType.dataType = ft.ArrayFeatureType.DOUBLE
    spec.description.metadata.shortDescription = (
        f"XVRC-27 {N}-in 1-out addchain: y = sum(x). Legit-count OOB vehicle."
    )
    spec.specificationVersion = max(spec.specificationVersion, 4)
    return spec


def find_coremlc() -> Path | None:
    for root in ("/Applications", "/Users/kolby/Applications"):
        try:
            hits = sorted(Path(root).glob("Xcode.app/Contents/usr/bin/coremlc"))
            if hits:
                return hits[0]
        except OSError:
            pass
    w = shutil.which("coremlc")
    return Path(w) if w else None


def main() -> int:
    from coremltools.models import utils as cmu

    spec = build_spec()
    cmu.save_spec(spec, str(TMP_MLMODEL.with_suffix(".mlmodel")))
    coremlc = find_coremlc()
    if not coremlc:
        print("[-] coremlc not found", file=sys.stderr)
        return 1
    if TMP_COMPILE.exists():
        shutil.rmtree(TMP_COMPILE)
    r = subprocess.run(
        [str(coremlc), "compile", str(TMP_MLMODEL.with_suffix(".mlmodel")),
         str(TMP_COMPILE)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
        return 1
    if OUT_MLC.exists():
        shutil.rmtree(OUT_MLC)
    shutil.copytree(TMP_COMPILE / "XVRC27_192in_1out_addchain.mlmodelc", OUT_MLC)
    print(f"[+] {OUT_MLC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())