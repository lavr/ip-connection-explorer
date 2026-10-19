#!/usr/bin/env bash
set -euo pipefail

REMOTE="origin"

usage() {
    cat <<USAGE
Usage: $0 <command> [<spec>] [options]

Commands:
  status                       Show the latest release tag
  app    [<spec>]              Tag a release and push it; CI builds and publishes it

Spec:
  patch | minor | major        Bump relative to the latest tag
  X.Y.Z                        Explicit version, must be higher than the latest tag
                               (required for the first release)
  omitted                      Ask interactively (requires a terminal)

Options:
  --yes                        Skip the confirmation prompt
  --dry-run                    Print the plan and exit before any change
  -h, --help                   Show this help

Non-interactive use needs the spec plus --yes; consent is never inferred from the
absence of a terminal. Relative specs are resolved against the current tags, so they
are not safe retry identifiers: prefer X.Y.Z when retrying a release whose outcome
is unknown.
USAGE
}

die() {
    echo "Error: $*" >&2
    exit 1
}

COMMAND=""
SPECS=()
ASSUME_YES=false
DRY_RUN=false

parse_args() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            -h|--help) usage; exit 0 ;;
            --yes)     ASSUME_YES=true ;;
            --dry-run) DRY_RUN=true ;;
            -*)        die "unknown option: $arg" ;;
            *)
                if [[ -z "$COMMAND" ]]; then
                    COMMAND="$arg"
                else
                    SPECS+=("$arg")
                fi
                ;;
        esac
    done

    [[ -n "$COMMAND" ]] || { usage >&2; exit 1; }

    local max_specs
    case "$COMMAND" in
        status) max_specs=0 ;;
        app)    max_specs=1 ;;
        *)      die "unknown command: $COMMAND" ;;
    esac

    if (( ${#SPECS[@]} > max_specs )); then
        die "$COMMAND takes at most $max_specs version spec(s), got ${#SPECS[@]}: ${SPECS[*]}"
    fi
    if [[ "$COMMAND" == "status" ]] && { $ASSUME_YES || $DRY_RUN; }; then
        die "status takes no options"
    fi

    local spec
    for spec in ${SPECS+"${SPECS[@]}"}; do
        [[ -n "$spec" ]] || die "empty version spec: pass patch, minor, major or X.Y.Z, or omit it"
    done
}

require_main() {
    local branch
    branch=$(git rev-parse --abbrev-ref HEAD)
    [[ "$branch" == "main" ]] || die "release.sh must be run from the main branch (current: $branch)"
}

require_clean_tree() {
    git diff --quiet --cached || die "index has staged changes; commit or unstage them first"
    git diff --quiet || die "worktree has uncommitted changes; commit or stash them first"
}

current_tag() {
    local out
    out=$(git tag --sort=-v:refname | grep -E '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || true)
    printf '%s' "${out%%$'\n'*}"
}

is_canonical_version() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

version_gt() {
    local a="$1" b="$2" a1 a2 a3 b1 b2 b3
    IFS='.' read -r a1 a2 a3 <<< "$a"
    IFS='.' read -r b1 b2 b3 <<< "$b"
    (( a1 != b1 )) && { (( a1 > b1 )); return; }
    (( a2 != b2 )) && { (( a2 > b2 )); return; }
    (( a3 > b3 ))
}

bump() {
    local version="$1" part="$2"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$version"
    case "$part" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
    esac
}

have_tty() {
    { exec 3<>/dev/tty; } 2>/dev/null || return 1
    exec 3>&-
    return 0
}

PICKED_VERSION=""

pick_version() {
    local current="$1" spec="${2:-}"

    if [[ -z "$current" ]]; then
        [[ -n "$spec" ]] || die "no previous tag to bump from; pass an explicit X.Y.Z"
        is_canonical_version "$spec" || die "no previous tag to bump from; pass an explicit X.Y.Z, not $spec"
        PICKED_VERSION="$spec"
        return 0
    fi

    is_canonical_version "$current" || die "latest tag $current is not a canonical X.Y.Z; release with an explicit version after fixing the tags"

    if [[ -n "$spec" ]]; then
        case "$spec" in
            patch|minor|major) PICKED_VERSION=$(bump "$current" "$spec") ;;
            *)
                is_canonical_version "$spec" || die "invalid version $spec: expected patch, minor, major or X.Y.Z without leading zeros"
                PICKED_VERSION="$spec"
                ;;
        esac
        version_gt "$PICKED_VERSION" "$current" || die "$PICKED_VERSION is not higher than the current $current"
        return 0
    fi

    have_tty || die "no terminal to ask on; pass a version spec (patch, minor, major or X.Y.Z)"

    local v_patch v_minor v_major choice
    v_patch=$(bump "$current" patch)
    v_minor=$(bump "$current" minor)
    v_major=$(bump "$current" major)

    {
        echo ""
        echo "Version (current: $current):"
        echo "  1) patch  -> $v_patch"
        echo "  2) minor  -> $v_minor"
        echo "  3) major  -> $v_major"
        printf "Choose [1/2/3]: "
    } > /dev/tty
    read -r choice < /dev/tty || die "no answer"
    case "$choice" in
        1) PICKED_VERSION="$v_patch" ;;
        2) PICKED_VERSION="$v_minor" ;;
        3) PICKED_VERSION="$v_major" ;;
        *) die "invalid choice: $choice" ;;
    esac
}

confirm() {
    $ASSUME_YES && return 0
    have_tty || die "no terminal to confirm on; pass --yes to consent explicitly"
    local ans
    printf "%s [y/N] " "$1" > /dev/tty
    read -r ans < /dev/tty || die "no answer"
    [[ "$ans" =~ ^[Yy]$ ]] || exit 0
}

require_absent_tag() {
    git tag -l "$1" | grep -q . && die "tag $1 already exists"
    return 0
}

status() {
    local tag; tag=$(current_tag)
    echo "latest tag: ${tag:-none}"
}

release_app() {
    local base; base=$(current_tag)
    pick_version "$base" "${SPECS[0]:-}"
    local version="$PICKED_VERSION"
    require_absent_tag "$version"

    echo ""
    echo "Plan:"
    echo "  tag $version at $(git rev-parse --short HEAD) (current: ${base:-none})"
    echo "  push $REMOTE main $version"
    echo ""
    if [[ -n "$base" ]]; then
        echo "Commits since $base:"
        git log --oneline "$base..HEAD"
    else
        echo "Commits:"
        git log --oneline
    fi
    echo ""
    $DRY_RUN && { echo "dry run: nothing changed"; return 0; }
    confirm "Create tag $version?"

    git tag "$version"
    git push --atomic "$REMOTE" main "$version"
    echo "Pushed tag: $version"
}

parse_args "$@"
cd "$(git rev-parse --show-toplevel)"

if [[ "$COMMAND" == "status" ]]; then
    status
    exit 0
fi

require_main
$DRY_RUN || require_clean_tree

case "$COMMAND" in
    app) release_app ;;
esac
