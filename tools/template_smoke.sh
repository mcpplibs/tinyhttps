#!/usr/bin/env bash
# Render and build every template in templates/ against THIS checkout.
#
# WHY THIS EXISTS AND WHY IT IS NOT `mcpp new`. `mcpp new --template tinyhttps`
# resolves the package from the index, so it can only ever exercise a version
# that has already been released. A template is part of the release it ships in;
# checking it after publishing means the first person to run `mcpp new` is the
# one who finds out it does not compile.
#
# So this renders each template the way mcpp's scaffolder does — the same
# placeholder vocabulary, `.in` suffix stripped, everything else copied — and
# then repoints the generated dependency at this working tree.
#
# The vocabulary below is mcpp's, from `src/scaffold/template.cppm`:
#   {{project.name}} {{project.namespace}} {{project.qualifiedName}}
#   {{template.package.namespace}} {{template.package.name}}
#   {{template.package.selector}} {{template.package.version}} {{template.name}}
# (`{{self.name}}` and `{{self.version}}` are a compatibility spelling of the
# two selector/version tokens and are not used here.)
#
# Usage: bash tools/template_smoke.sh        (mcpp on PATH, or $MCPP)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MCPP_BIN="${MCPP:-$(command -v mcpp || true)}"
if [[ -z "$MCPP_BIN" || ! -x "$MCPP_BIN" ]]; then
    echo "FATAL: put mcpp on PATH or set MCPP=/path/to/mcpp" >&2
    exit 1
fi

SELF_NS="$(sed -n 's/^namespace *= *"\([^"]*\)".*/\1/p' "$ROOT/mcpp.toml" | head -1)"
SELF_NAME="$(sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$ROOT/mcpp.toml" | head -1)"
SELF_VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/mcpp.toml" | head -1)"
echo "library: $SELF_NS.$SELF_NAME@$SELF_VERSION"

# Generated projects live inside the repo so target/ keeps them out of git.
# The depth is fixed, so each one reaches the library root at ../../..
TMP="$ROOT/target/template-smoke"
REL_ROOT="../../.."
rm -rf "$TMP"
mkdir -p "$TMP"

fail=0
for tdir in "$ROOT"/templates/*/; do
    tname="$(basename "$tdir")"
    proj="$TMP/smoke_$tname"
    mkdir -p "$proj"

    if [[ ! -f "$tdir/template.toml" ]]; then
        echo "FAIL: template '$tname' has no template.toml" >&2
        fail=1
        continue
    fi

    while IFS= read -r -d '' f; do
        rel="${f#"$tdir"}"
        [[ "$rel" == "template.toml" ]] && continue      # metadata, not content
        dest="$proj/${rel%.in}"
        mkdir -p "$(dirname "$dest")"
        if [[ "$f" == *.in ]]; then
            sed -e "s/{{project\.name}}/smoke_$tname/g" \
                -e "s/{{project\.namespace}}/$SELF_NS/g" \
                -e "s/{{project\.qualifiedName}}/$SELF_NS.smoke_$tname/g" \
                -e "s/{{template\.package\.namespace}}/$SELF_NS/g" \
                -e "s/{{template\.package\.name}}/$SELF_NAME/g" \
                -e "s/{{template\.package\.selector}}/$SELF_NAME/g" \
                -e "s/{{template\.package\.version}}/$SELF_VERSION/g" \
                -e "s/{{template\.name}}/$tname/g" "$f" > "$dest"
        else
            cp "$f" "$dest"
        fi
    done < <(find "$tdir" -type f -print0)

    # An unrendered placeholder is a token this script does not know and mcpp
    # might not either. Catch it here rather than in the compiler's output.
    if grep -rn "{{" "$proj" >/dev/null 2>&1; then
        echo "FAIL: template '$tname' left an unrendered placeholder:" >&2
        grep -rn "{{" "$proj" >&2
        fail=1
        continue
    fi

    # Build against this checkout rather than the index, which may not have this
    # version yet. Relative on purpose: an absolute path needs TOML escaping on
    # Windows.
    sed -i.bak "s|^\( *\)$SELF_NAME *= *\"[^\"]*\"|\1$SELF_NAME = { path = \"$REL_ROOT\" }|" \
        "$proj/mcpp.toml"
    rm -f "$proj/mcpp.toml.bak"
    grep -q "path = \"$REL_ROOT\"" "$proj/mcpp.toml" || {
        echo "FAIL: template '$tname' declares no '$SELF_NAME = \"...\"' dependency" >&2
        fail=1
        continue
    }

    echo "=== template: $tname ==="
    if [[ -f "$proj/src/main.cpp" ]]; then
        # A bin template: build AND run it. Every template here exits 0 without
        # network or credentials, so this stays honest in an offline CI job.
        (cd "$proj" && "$MCPP_BIN" run) || { echo "FAIL: template '$tname'" >&2; fail=1; }
    else
        (cd "$proj" && "$MCPP_BIN" build) || { echo "FAIL: template '$tname'" >&2; fail=1; }
    fi
done

# Exactly one template may be the default; more than one is an error mcpp
# reports only when someone runs `mcpp new`.
defaults="$(grep -l "^default *= *true" "$ROOT"/templates/*/template.toml 2>/dev/null | wc -l)"
if [[ "$defaults" -gt 1 ]]; then
    echo "FAIL: $defaults templates declare default = true; at most one may" >&2
    fail=1
fi

if [[ $fail -eq 0 ]]; then
    echo "All templates render, build and run."
fi
exit $fail
