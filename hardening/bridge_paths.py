"""Filesystem allowlist for the MCP bridge (local fork addition).

Every path the bridge is asked to read, write, list or add must resolve (after
normalization, symlink/junction resolution and case folding) to a location inside
one of the configured roots (``allowed_paths`` in config.json). Anything else raises
SafetyError, which the bridge reports as a 'Policy: ...' error.

Scope and limits:
  * Enforced on every handler that takes a path, on the data source of every layer a
    handler reads or edits, and on string parameters of run_geoprocessing.
  * NOT enforceable once ``allow_execute_python`` is on: arbitrary code can open any
    file. Keep execute_python off if the allowlist matters.
  * Bare (non-path) output names written by geoprocessing tools land in the current
    workspace, so the effective workspace must itself be inside an allowed root.
  * arcpy ``%scratchGDB%``-style tokens and tool-internal temp files are not checked.
No arcpy import -> importable and testable anywhere.
"""
import os
import re

try:  # same class the bridge catches, whichever way this module was imported
    from hardening.bridge_safety import SafetyError
except ImportError:  # pragma: no cover - flat import in the unit tests
    from bridge_safety import SafetyError

_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|//)")
_RAW_NS = ("\\\\?\\", "\\\\.\\")
_EMBEDDED_ABS = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|(?:^|(?<=\s))(?:\\\\|//)")
_SEP = re.compile(r"[\\/]")
_MEMORY = ("memory", "in_memory")


def _norm(p):
    p = os.path.normpath(p.replace("/", os.sep))
    try:
        p = os.path.realpath(p)
    except (OSError, ValueError):
        p = os.path.abspath(p)
    return os.path.normcase(p)


def _is_memory(p):
    parts = [c for c in _SEP.split(p.strip().lower()) if c]
    return bool(parts) and parts[0] in _MEMORY and ".." not in parts


class PathPolicy:
    def __init__(self, roots, enforce=True):
        if isinstance(roots, str):
            roots = [roots]
        self.enforce = bool(enforce)
        self.roots_display = [str(r) for r in (roots or [])]
        self._roots = [_norm(str(r)).rstrip(os.sep) + os.sep for r in (roots or []) if str(r).strip()]

    def is_allowed(self, p):
        n = _norm(p) + os.sep
        return any(n.startswith(r) for r in self._roots)

    def require(self, p, what="path", allow_memory=True):
        """Raise SafetyError unless `p` is an absolute local path inside an allowed root."""
        if not self.enforce:
            return
        if not isinstance(p, str) or not p.strip():
            raise SafetyError("%s is empty; an absolute path inside the allowed folders is required." % what)
        s = p.strip().strip("\"'")
        if allow_memory and _is_memory(s):
            return
        if "://" in s:
            raise SafetyError("%s '%s' is a URL; only local paths inside %s are allowed."
                              % (what, p, self.roots_display))
        if s.startswith(_RAW_NS) or not _ABS.match(s):
            raise SafetyError("%s '%s' must be an absolute local path (e.g. C:/folder/file) inside %s."
                              % (what, p, self.roots_display))
        if not self.is_allowed(s):
            raise SafetyError("%s '%s' is outside the allowed folders %s. "
                              "Edit allowed_paths in ~/.arcgis_mcp/config.json to change this."
                              % (what, p, self.roots_display))

    def check_source(self, src, what="layer data source"):
        """Data source of a map layer. Web/service layers and sourceless layers are not files."""
        if not self.enforce or not src or not isinstance(src, str) or "://" in src:
            return
        self.require(src, what)

    def check_gp_params(self, params, layer_source=None, workspace=None):
        """Check every string inside run_geoprocessing parameters.

        layer_source(name) -> data source path or None, to catch layer names that point
        at data outside the allowed folders. workspace is used to anchor relative paths.
        """
        if not self.enforce:
            return
        if workspace is not None:
            self.require(workspace, "current workspace")
        for p in self._walk(params):
            self._check_string(p, layer_source, workspace)

    def _walk(self, obj):
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from self._walk(v)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                yield from self._walk(v)

    def _check_string(self, s, layer_source, workspace):
        s = s.replace('"', "").replace("'", "")
        if "://" in s:
            raise SafetyError("parameter '%s' contains a URL; only local paths inside %s are allowed."
                              % (s, self.roots_display))
        for seg in s.split(";"):
            seg = seg.strip()
            if not seg or _is_memory(seg):
                continue
            starts = [m.start() for m in _EMBEDDED_ABS.finditer(seg)]
            if starts:
                for i in starts:
                    self.require(seg[i:], "parameter path", allow_memory=False)
            elif _SEP.search(seg):
                if ".." in _SEP.split(seg):
                    raise SafetyError("parameter '%s' contains '..'; use a full path inside %s."
                                      % (seg, self.roots_display))
                if not workspace:
                    raise SafetyError("parameter '%s' is a relative path and no workspace is set." % seg)
                self.require(os.path.join(workspace, seg), "parameter path", allow_memory=False)
            elif layer_source is not None and not re.search(r"[*?]", seg):
                src = layer_source(seg)
                if src:
                    self.check_source(src, "layer '%s' data source" % seg)
