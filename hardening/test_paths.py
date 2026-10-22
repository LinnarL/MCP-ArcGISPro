"""Unit tests for the path allowlist. Pure Python, no arcpy required (Windows paths).
Run: python hardening/test_paths.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

import bridge_config as bc
import bridge_paths as bp
from bridge_safety import SafetyError

_passed = 0
_failed = 0


def check(label, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print("  PASS:", label)
    else:
        _failed += 1
        print("  FAIL:", label)


def denied(fn, *a, **k):
    try:
        fn(*a, **k)
    except SafetyError:
        return True
    return False


def test_require():
    print("[paths.require]")
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "Lokal GIS")
        sib = os.path.join(tmp, "Lokal GIS-evil")
        out = os.path.join(tmp, "elsewhere")
        for d in (root, sib, out):
            os.makedirs(d)
        P = bp.PathPolicy([root])
        fwd = root.replace("\\", "/")

        check("file inside root allowed", not denied(P.require, root + "\\a\\b.shp"))
        check("forward slashes allowed", not denied(P.require, fwd + "/a/b.shp"))
        check("root itself allowed", not denied(P.require, root))
        check("case-insensitive", not denied(P.require, root.upper() + "\\x"))
        check("gdb path inside root allowed", not denied(P.require, root + "\\d.gdb\\fc"))
        check("outside root denied", denied(P.require, out + "\\a.shp"))
        check("sibling with same prefix denied", denied(P.require, sib + "\\a.shp"))
        check(".. traversal denied", denied(P.require, root + "\\..\\elsewhere\\a.shp"))
        check("relative path denied", denied(P.require, "data\\a.shp"))
        check("bare name denied", denied(P.require, "roads"))
        check("empty denied", denied(P.require, ""))
        check("None denied", denied(P.require, None))
        check("URL denied", denied(P.require, "https://example.com/FeatureServer/0"))
        check("UNC denied", denied(P.require, "\\\\server\\share\\a.shp"))
        check("raw \\\\?\\ prefix denied", denied(P.require, "\\\\?\\" + out + "\\a.shp"))
        check("memory workspace allowed by default", not denied(P.require, "memory\\tmp"))
        check("memory denied when disallowed", denied(P.require, "memory\\tmp", allow_memory=False))
        check("memory with .. denied", denied(P.require, "memory\\..\\x"))
        check("quoted path unwrapped", not denied(P.require, '"' + root + '\\a.shp"'))

        # junction inside the root that points outside must not be a way out
        link = os.path.join(root, "link")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, out], capture_output=True)
        if r.returncode == 0:
            check("junction escaping root denied", denied(P.require, link + "\\a.shp"))
        else:
            print("  SKIP: could not create junction")

        off = bp.PathPolicy([root], enforce=False)
        check("enforce=False allows everything", not denied(off.require, out + "\\a.shp"))
        check("empty roots deny everything", denied(bp.PathPolicy([]).require, root + "\\a"))
        check("string root accepted", not denied(bp.PathPolicy(root).require, root + "\\a"))


def test_check_source():
    print("[paths.check_source]")
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "ok")
        os.makedirs(root)
        P = bp.PathPolicy([root])
        check("None source ok (group/basemap)", not denied(P.check_source, None))
        check("service URL ok (not a file)", not denied(P.check_source, "https://x/FeatureServer/0"))
        check("inside ok", not denied(P.check_source, root + "\\a.gdb\\fc"))
        check("outside denied", denied(P.check_source, tmp + "\\other\\a.shp"))


def test_gp_params():
    print("[paths.check_gp_params]")
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "ok")
        bad = os.path.join(tmp, "bad")
        os.makedirs(root)
        os.makedirs(bad)
        P = bp.PathPolicy([root])
        ws = root + "\\w.gdb"
        sources = {"inside": root + "\\a.shp", "outside": bad + "\\b.shp"}
        ls = sources.get

        def run(params, workspace=ws, layer_source=ls):
            P.check_gp_params(params, layer_source=layer_source, workspace=workspace)

        check("all-inside Buffer ok",
              not denied(run, [root + "\\a.shp", root + "\\o.shp", "500 Meters", "ROUND", "NONE"]))
        check("output outside denied", denied(run, [root + "\\a.shp", bad + "\\o.shp", "5 Meters"]))
        check("input outside denied", denied(run, [bad + "\\a.shp", root + "\\o.shp"]))
        check("multivalue ';' with one outside denied", denied(run, [root + "\\a.shp;" + bad + "\\b.shp", "x"]))
        check("value-table 'path FIELD' inside ok", not denied(run, [root + "\\a.shp NAME", "x"]))
        check("value-table 'path FIELD' outside denied", denied(run, [bad + "\\a.shp NAME", "x"]))
        check("quoted path with spaces inside ok", not denied(run, ["'" + root + "\\a b.shp'"]))
        check("nested list checked", denied(run, [[root + "\\a.shp", bad + "\\b.shp"]]))
        check("dict values checked", denied(run, [{"in": bad + "\\b.shp"}]))
        check("URL param denied", denied(run, ["https://x/y"]))
        check(".. in relative param denied", denied(run, ["..\\..\\x.shp"]))
        check("relative path anchored to allowed workspace ok", not denied(run, ["sub\\x.shp"]))
        check("relative path with no workspace denied", denied(run, ["sub\\x.shp"], workspace=None))
        check("layer name -> inside source ok", not denied(run, ["inside", "out"]))
        check("layer name -> outside source denied", denied(run, ["outside", "out"]))
        check("memory output ok", not denied(run, [root + "\\a.shp", "memory\\tmp"]))
        check("distance / keyword strings ok", not denied(run, ["10 Meters", "ALL", "FULL", "#"]))
        check("SQL with slash and quotes ok", not denied(run, ["A / B > 2 AND N = 'x/y'"]))
        check("non-string params ignored", not denied(run, [1, 2.5, True, None]))
        check("workspace outside allowed denied", denied(run, ["500 Meters"], workspace=bad))
        check("wildcard token not looked up as layer", not denied(run, ["*"]))


def test_config_defaults():
    print("[config]")
    cfg = bc.BridgeConfig()
    check("allowlist enforced by default", cfg.enforce_paths is True)
    check("default root is C:/Lokal GIS", cfg.allowed_paths == ["C:/Lokal GIS"])
    check("default root normalizes to a single allowed root",
          bp.PathPolicy(cfg.allowed_paths).is_allowed("c:\\lokal gis\\x\\y.shp"))
    check("C:/Lokal GISX not allowed by default root",
          not bp.PathPolicy(cfg.allowed_paths).is_allowed("C:/Lokal GISX/y.shp"))


if __name__ == "__main__":
    test_require()
    test_check_source()
    test_gp_params()
    test_config_defaults()
    print("\n{} passed, {} failed".format(_passed, _failed))
    sys.exit(1 if _failed else 0)
