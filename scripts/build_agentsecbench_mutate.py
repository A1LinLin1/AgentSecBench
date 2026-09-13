"""Build isolated, ground-truth mutation repositories for AgentSecBench-Mutate.

The frozen corpus is never modified.  Each selected repository is exported from
its pinned commit into ``benchmarks/derived/`` and receives five small source
files whose semantic oracle is saved alongside the derived manifest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = BASE_DIR / "dataset" / "corpus_manifest.csv"
DEFAULT_PILOT = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_ROOT = BASE_DIR / "benchmarks" / "derived" / "agentsecbench_mutate_v1"
DEFAULT_SEED = "agentsecbench-mutate-v1-20260831"


def score(seed: str, sample_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{sample_id}".encode("utf-8")).hexdigest()


def select_rows(
    corpus: list[dict[str, str]],
    pilot_repos: set[str],
    excluded_sample_ids: set[str],
    seed: str,
    python_count: int,
    ts_count: int,
) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    for language, count in (("Python", python_count), ("TypeScript", ts_count)):
        candidates = [
            row for row in corpus
            if row["repo"] not in pilot_repos
            and row["sample_id"] not in excluded_sample_ids
            and row["dominant_language"] == language
        ]
        candidates.sort(key=lambda row: (score(seed, row["sample_id"]), row["sample_id"]))
        if len(candidates) < count:
            raise RuntimeError(f"only {len(candidates)} eligible {language} repositories; need {count}")
        selected.extend(candidates[:count])
    return sorted(selected, key=lambda row: (row["dominant_language"], row["sample_id"]))


def python_mutations(sample_id: str) -> list[dict]:
    prefix = f"MUT-{sample_id}-PY"
    return [
        {
            "mutation_id": f"{prefix}-01",
            "file": f"asb_mutations/{sample_id.lower()}_tool_command.py",
            "category": "command_execution",
            "symbol": "asb_mutate_tool_command",
            "oracle": {"dependency": True, "source_type": "agent_tool_parameter", "guard_kind": None, "polarity": "positive"},
            "source": "import subprocess\n\n@mcp.tool()\ndef asb_mutate_tool_command(command):\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-02",
            "file": f"asb_mutations/{sample_id.lower()}_env_command.py",
            "category": "command_execution",
            "symbol": "asb_mutate_env_command",
            "oracle": {"dependency": True, "source_type": "source_api", "guard_kind": None, "polarity": "positive"},
            "source": "import os\nimport subprocess\n\ndef asb_mutate_env_command():\n    command = os.getenv('ASB_MUTATION_COMMAND')\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-03",
            "file": f"asb_mutations/{sample_id.lower()}_network.py",
            "category": "network_access",
            "symbol": "asb_mutate_network",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive"},
            "source": "import requests\n\ndef asb_mutate_network(url):\n    return requests.get(url)\n",
        },
        {
            "mutation_id": f"{prefix}-04",
            "file": f"asb_mutations/{sample_id.lower()}_constant.py",
            "category": "command_execution",
            "symbol": "asb_mutate_constant",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_constant"},
            "source": "import subprocess\n\ndef asb_mutate_constant(external_command):\n    command = 'echo asb-safe'\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-05",
            "file": f"asb_mutations/{sample_id.lower()}_unrelated_guard.py",
            "category": "command_execution",
            "symbol": "asb_mutate_unrelated_guard",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "negative_guard"},
            "source": "import subprocess\n\ndef asb_mutate_unrelated_guard(command, approved):\n    if approved:\n        print('audit only')\n    return subprocess.run(command, shell=True)\n",
        },
    ]


def typescript_mutations(sample_id: str) -> list[dict]:
    prefix = f"MUT-{sample_id}-TS"
    return [
        {
            "mutation_id": f"{prefix}-01",
            "file": f"asb_mutations/{sample_id.lower()}_direct_command.ts",
            "category": "command_execution",
            "symbol": "asbMutateDirectCommand",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive"},
            "source": "export function asbMutateDirectCommand(command: string) {\n  return spawn('sh', ['-c', command]);\n}\n",
        },
        {
            "mutation_id": f"{prefix}-02",
            "file": f"asb_mutations/{sample_id.lower()}_json_command.ts",
            "category": "command_execution",
            "symbol": "asbMutateJsonCommand",
            "oracle": {"dependency": True, "source_type": "source_api", "guard_kind": None, "polarity": "positive"},
            "source": "export function asbMutateJsonCommand() {\n  const command = request.json();\n  return spawn('sh', ['-c', command]);\n}\n",
        },
        {
            "mutation_id": f"{prefix}-03",
            "file": f"asb_mutations/{sample_id.lower()}_network.ts",
            "category": "network_access",
            "symbol": "asbMutateNetwork",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive"},
            "source": "export function asbMutateNetwork(url: string) {\n  return fetch(url);\n}\n",
        },
        {
            "mutation_id": f"{prefix}-04",
            "file": f"asb_mutations/{sample_id.lower()}_constant.ts",
            "category": "command_execution",
            "symbol": "asbMutateConstant",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_constant"},
            "source": "export function asbMutateConstant(externalCommand: string) {\n  const command = 'echo asb-safe';\n  return spawn('sh', ['-c', command]);\n}\n",
        },
        {
            "mutation_id": f"{prefix}-05",
            "file": f"asb_mutations/{sample_id.lower()}_unrelated_guard.ts",
            "category": "command_execution",
            "symbol": "asbMutateUnrelatedGuard",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "negative_guard"},
            "source": "export function asbMutateUnrelatedGuard(command: string, approved: boolean) {\n  if (approved) console.log('audit only');\n  return spawn('sh', ['-c', command]);\n}\n",
        },
    ]


def python_mutations_v2(sample_id: str) -> list[dict]:
    """Independent, source-level probes for a frozen v2.4 evaluation.

    These are intentionally not copies of the v1 snippets: they test a tool
    boundary, transformation, parameter-backed extractor, API source, target
    network sink, constant overwrite, and a structurally dominating guard.
    """
    prefix = f"MUT-{sample_id}-PY2"
    return [
        {
            "mutation_id": f"{prefix}-01",
            "file": f"asb_mutations/{sample_id.lower()}_tool_boundary.py",
            "category": "command_execution",
            "symbol": "asb_mutate_tool_boundary",
            "oracle": {"dependency": True, "source_type": "agent_tool_parameter", "guard_kind": None, "polarity": "positive_tool_boundary"},
            "source": "import subprocess\n\n@server.tool\ndef asb_mutate_tool_boundary(action):\n    return subprocess.run(['sh', '-c', action])\n",
        },
        {
            "mutation_id": f"{prefix}-02",
            "file": f"asb_mutations/{sample_id.lower()}_transform.py",
            "category": "command_execution",
            "symbol": "asb_mutate_transform",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_transformation"},
            "source": "import subprocess\n\ndef asb_mutate_transform(raw_command):\n    normalized = raw_command.strip()\n    return subprocess.run(normalized, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-03",
            "file": f"asb_mutations/{sample_id.lower()}_extractor.py",
            "category": "command_execution",
            "symbol": "asb_mutate_extractor",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_parameter_backed_extractor"},
            "source": "import subprocess\n\ndef asb_mutate_extractor(payload):\n    command = payload.get('command')\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-04",
            "file": f"asb_mutations/{sample_id.lower()}_api_source.py",
            "category": "command_execution",
            "symbol": "asb_mutate_api_source",
            "oracle": {"dependency": True, "source_type": "source_api", "guard_kind": None, "polarity": "positive_source_api"},
            "source": "import os\nimport subprocess\n\ndef asb_mutate_api_source():\n    runtime_command = os.getenv('ASB_RUNTIME_COMMAND')\n    return subprocess.run(runtime_command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-05",
            "file": f"asb_mutations/{sample_id.lower()}_network_sink.py",
            "category": "network_access",
            "symbol": "asb_mutate_network_sink",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_network_sink"},
            "source": "import requests\n\ndef asb_mutate_network_sink(destination):\n    return requests.get(destination, timeout=2)\n",
        },
        {
            "mutation_id": f"{prefix}-06",
            "file": f"asb_mutations/{sample_id.lower()}_overwrite.py",
            "category": "command_execution",
            "symbol": "asb_mutate_overwrite",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_constant_overwrite"},
            "source": "import subprocess\n\ndef asb_mutate_overwrite(untrusted_command):\n    selected_command = 'echo asb-fixed'\n    return subprocess.run(selected_command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-07",
            "file": f"asb_mutations/{sample_id.lower()}_dominating_guard.py",
            "category": "command_execution",
            "symbol": "asb_mutate_dominating_guard",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": "dominating_if", "polarity": "positive_dominating_guard"},
            "source": "import subprocess\n\ndef asb_mutate_dominating_guard(command):\n    if command:\n        return subprocess.run(command, shell=True)\n    return None\n",
        },
    ]


def python_mutations_v3(sample_id: str) -> list[dict]:
    """A structurally distinct, post-freeze robustness suite for v2.4.

    Unlike v1/v2, this profile exercises subscript extraction, keyword sink
    arguments, async tool boundaries, file-backed source APIs, and assertions.
    It is intentionally introduced only after the v2.4 engine is frozen.
    """
    prefix = f"MUT-{sample_id}-PY3"
    return [
        {
            "mutation_id": f"{prefix}-01",
            "file": f"asb_mutations/{sample_id.lower()}_async_tool.py",
            "category": "command_execution",
            "symbol": "asb_mutate_async_tool",
            "oracle": {"dependency": True, "source_type": "agent_tool_parameter", "guard_kind": None, "polarity": "positive_async_tool"},
            "source": "import subprocess\n\n@mcp.tool\nasync def asb_mutate_async_tool(action):\n    return subprocess.Popen(['sh', '-c', action])\n",
        },
        {
            "mutation_id": f"{prefix}-02",
            "file": f"asb_mutations/{sample_id.lower()}_subscript.py",
            "category": "command_execution",
            "symbol": "asb_mutate_subscript",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_subscript_extraction"},
            "source": "import subprocess\n\ndef asb_mutate_subscript(event):\n    selected = event['command']\n    return subprocess.run(selected, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-03",
            "file": f"asb_mutations/{sample_id.lower()}_keyword_sink.py",
            "category": "command_execution",
            "symbol": "asb_mutate_keyword_sink",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_keyword_sink"},
            "source": "import subprocess\n\ndef asb_mutate_keyword_sink(command):\n    return subprocess.run(args=command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-04",
            "file": f"asb_mutations/{sample_id.lower()}_file_source.py",
            "category": "command_execution",
            "symbol": "asb_mutate_file_source",
            "oracle": {"dependency": True, "source_type": "source_api", "guard_kind": None, "polarity": "positive_file_source_api"},
            "source": "from pathlib import Path\nimport subprocess\n\ndef asb_mutate_file_source():\n    command = Path('/tmp/asb-command').read_text()\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-05",
            "file": f"asb_mutations/{sample_id.lower()}_transform.py",
            "category": "command_execution",
            "symbol": "asb_mutate_transform_v3",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_nested_transformation"},
            "source": "import subprocess\n\ndef asb_mutate_transform_v3(raw):\n    prepared = ('%s' % raw).strip()\n    return subprocess.run(prepared, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-06",
            "file": f"asb_mutations/{sample_id.lower()}_constant.py",
            "category": "command_execution",
            "symbol": "asb_mutate_constant_v3",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_constant"},
            "source": "import subprocess\n\ndef asb_mutate_constant_v3(untrusted):\n    chosen = 'echo asb-v3-fixed'\n    return subprocess.run(chosen, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-07",
            "file": f"asb_mutations/{sample_id.lower()}_assert_guard.py",
            "category": "command_execution",
            "symbol": "asb_mutate_assert_guard",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": "preceding_assert", "polarity": "positive_assert_guard"},
            "source": "import subprocess\n\ndef asb_mutate_assert_guard(command):\n    assert command\n    return subprocess.run(command, shell=True)\n",
        },
    ]


def python_mutations_v4(sample_id: str) -> list[dict]:
    """Balanced, post-freeze semantic-confounder probes for Security-ADG v2.4.

    This suite is intentionally evaluated on source repositories disjoint from
    v1, v2, and v3.  Four positive cases represent distinct local trust-source
    paths, while four negative cases retain a detectable security-sensitive
    operation but deliberately break the input-to-effect dependency.
    """
    prefix = f"MUT-{sample_id}-PY4"
    return [
        {
            "mutation_id": f"{prefix}-01",
            "file": f"asb_mutations/{sample_id.lower()}_tool_argv.py",
            "category": "command_execution",
            "symbol": "asb_mutate_tool_argv",
            "oracle": {"dependency": True, "source_type": "agent_tool_parameter", "guard_kind": None, "polarity": "positive_tool_argv"},
            "source": "import subprocess\n\n@server.tool\ndef asb_mutate_tool_argv(action):\n    argv = ['sh', '-c', action]\n    return subprocess.run(argv)\n",
        },
        {
            "mutation_id": f"{prefix}-02",
            "file": f"asb_mutations/{sample_id.lower()}_mapping_transform.py",
            "category": "command_execution",
            "symbol": "asb_mutate_mapping_transform",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": None, "polarity": "positive_mapping_transform"},
            "source": "import subprocess\n\ndef asb_mutate_mapping_transform(payload):\n    raw = payload['command']\n    prepared = f'{raw}'.strip()\n    return subprocess.run(prepared, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-03",
            "file": f"asb_mutations/{sample_id.lower()}_environment.py",
            "category": "command_execution",
            "symbol": "asb_mutate_environment",
            "oracle": {"dependency": True, "source_type": "source_api", "guard_kind": None, "polarity": "positive_environment_source"},
            "source": "import os\nimport subprocess\n\ndef asb_mutate_environment():\n    runtime_value = os.getenv('ASB_V4_COMMAND')\n    return subprocess.run(runtime_value, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-04",
            "file": f"asb_mutations/{sample_id.lower()}_guarded.py",
            "category": "command_execution",
            "symbol": "asb_mutate_guarded",
            "oracle": {"dependency": True, "source_type": "function_parameter", "guard_kind": "dominating_if", "polarity": "positive_guarded_dependency"},
            "source": "import subprocess\n\ndef asb_mutate_guarded(command):\n    if command.startswith('echo '):\n        return subprocess.run(command, shell=True)\n    return None\n",
        },
        {
            "mutation_id": f"{prefix}-05",
            "file": f"asb_mutations/{sample_id.lower()}_constant_overwrite.py",
            "category": "command_execution",
            "symbol": "asb_mutate_constant_overwrite",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_constant_overwrite"},
            "source": "import subprocess\n\ndef asb_mutate_constant_overwrite(command):\n    command = 'echo asb-v4-fixed'\n    return subprocess.run(command, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-06",
            "file": f"asb_mutations/{sample_id.lower()}_dead_input.py",
            "category": "command_execution",
            "symbol": "asb_mutate_dead_input",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_dead_input"},
            "source": "import subprocess\n\ndef asb_mutate_dead_input(external_command):\n    external_command.strip()\n    selected = 'echo asb-v4-safe'\n    return subprocess.run(selected, shell=True)\n",
        },
        {
            "mutation_id": f"{prefix}-07",
            "file": f"asb_mutations/{sample_id.lower()}_literal_argv.py",
            "category": "command_execution",
            "symbol": "asb_mutate_literal_argv",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_literal_argv"},
            "source": "import subprocess\n\ndef asb_mutate_literal_argv(command):\n    return subprocess.run(['echo', 'asb-v4-safe'])\n",
        },
        {
            "mutation_id": f"{prefix}-08",
            "file": f"asb_mutations/{sample_id.lower()}_discarded_source.py",
            "category": "command_execution",
            "symbol": "asb_mutate_discarded_source",
            "oracle": {"dependency": False, "source_type": None, "guard_kind": None, "polarity": "negative_discarded_source"},
            "source": "import os\nimport subprocess\n\ndef asb_mutate_discarded_source():\n    ignored = os.getenv('ASB_V4_COMMAND')\n    return subprocess.run('echo asb-v4-safe', shell=True)\n",
        },
    ]


def run(command: list[str], cwd: Path | None = None) -> str:
    if cwd is not None:
        cwd = cwd.resolve()
    if cwd is not None and command and command[0] == "git":
        command = ["git", "-c", f"safe.directory={cwd.as_posix()}", *command[1:]]
    completed = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def extract_archive(source: Path, commit: str, destination: Path) -> None:
    command = ["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source), "archive", "--format=tar", commit]
    # Capturing the finite archive first avoids a Windows pipe race observed
    # with tarfile stream mode, and lets us report Git's actual stderr.
    process = subprocess.run(command, capture_output=True, check=False)
    if process.returncode:
        stderr = process.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git archive failed for {source}: {stderr}")
    if not process.stdout:
        raise RuntimeError(f"git archive produced no bytes for {source} at {commit}")
    with tarfile.open(fileobj=io.BytesIO(process.stdout), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if member.isdir() or path.is_absolute() or ".." in path.parts:
                continue
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isfile():
                content = archive.extractfile(member)
                if content is not None:
                    target.write_bytes(content.read())


def build_one(row: dict[str, str], root: Path, suite: str, mutation_profile: str) -> tuple[dict, list[dict]]:
    destination = root / "repos" / row["sample_id"]
    if destination.exists():
        raise RuntimeError(f"derived destination already exists: {destination}")
    destination.mkdir(parents=True)
    source = BASE_DIR / row["repository_path"]
    extract_archive(source, row["git_commit"], destination)
    if mutation_profile in {"v2_python", "v3_python", "v4_python"}:
        if row["dominant_language"] != "Python":
            raise RuntimeError(f"{mutation_profile} profile only supports Python repositories")
        profiles = {
            "v2_python": python_mutations_v2,
            "v3_python": python_mutations_v3,
            "v4_python": python_mutations_v4,
        }
        mutations = profiles[mutation_profile](row["sample_id"])
    else:
        mutations = python_mutations(row["sample_id"]) if row["dominant_language"] == "Python" else typescript_mutations(row["sample_id"])
    for mutation in mutations:
        path = destination / mutation["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(mutation["source"], encoding="utf-8", newline="\n")
    run(["git", "init", "--quiet"], destination)
    run(["git", "add", "--all"], destination)
    run([
        "git", "-c", "user.name=AgentSecBench Mutation Builder", "-c", "user.email=mutation-benchmark@invalid",
        "commit", "--quiet", "--no-gpg-sign", "-m", f"{suite} seeds for {row['sample_id']}",
    ], destination)
    derived_commit = run(["git", "rev-parse", "HEAD"], destination)
    derived_row = dict(row)
    derived_row.update({
        "repository_path": destination.relative_to(BASE_DIR).as_posix(),
        "git_commit": derived_commit,
        "default_branch": suite,
        "remote_url": "",
        "is_shallow_clone": "false",
        "snapshot_mode": "derived_mutation_worktree",
        "working_tree_clean": "true",
        "source_sample_id": row["sample_id"],
        "source_repo": row["repo"],
        "source_git_commit": row["git_commit"],
        "mutation_suite": suite,
        "experiment_split": "mutation_evaluation",
        "use_for_method_tuning": "false",
    })
    for mutation in mutations:
        mutation.update({
            "source_sample_id": row["sample_id"],
            "source_repo": row["repo"],
            "source_git_commit": row["git_commit"],
            "derived_commit": derived_commit,
            "language": row["dominant_language"],
        })
    return derived_row, mutations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--pilot", type=Path, default=DEFAULT_PILOT)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--suite", help="Suite identifier stored in derived provenance (defaults to root directory name).")
    parser.add_argument("--mutation-profile", choices=("v1", "v2_python", "v3_python", "v4_python"), default="v1")
    parser.add_argument("--exclude-catalog", type=Path, action="append", help="Catalog whose source_sample_id values must not be reused. May be specified more than once.")
    parser.add_argument("--exclude-sample-id", action="append", default=[], help="Additional corpus sample ID to exclude (for platform-incompatible archives).")
    parser.add_argument("--python-repositories", type=int, default=6)
    parser.add_argument("--typescript-repositories", type=int, default=4)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    # CLI users commonly pass relative paths.  Normalize once so that derived
    # provenance can always be expressed relative to BASE_DIR on Windows too.
    args.corpus = args.corpus.resolve()
    args.pilot = args.pilot.resolve()
    args.root = args.root.resolve()
    if args.exclude_catalog:
        args.exclude_catalog = [path.resolve() for path in args.exclude_catalog]
    with args.corpus.open("r", encoding="utf-8-sig", newline="") as handle:
        corpus = list(csv.DictReader(handle))
    with args.pilot.open("r", encoding="utf-8-sig", newline="") as handle:
        pilot_repos = {row["repo"] for row in csv.DictReader(handle)}
    excluded_sample_ids: set[str] = set(args.exclude_sample_id)
    for catalog_path in args.exclude_catalog or []:
        excluded_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        excluded_sample_ids.update(item["source_sample_id"] for item in excluded_catalog["mutations"])
    suite = args.suite or args.root.name
    selected = select_rows(corpus, pilot_repos, excluded_sample_ids, args.seed, args.python_repositories, args.typescript_repositories)
    print(json.dumps({"suite": suite, "profile": args.mutation_profile, "seed": args.seed, "excluded_source_sample_ids": sorted(excluded_sample_ids), "selected": [{"sample_id": row["sample_id"], "repo": row["repo"], "language": row["dominant_language"]} for row in selected]}, ensure_ascii=False, indent=2))
    if args.dry_run:
        return 0
    if args.root.exists():
        raise SystemExit(f"refusing to overwrite existing benchmark root: {args.root}")
    args.root.mkdir(parents=True)
    derived_rows, mutations = [], []
    for row in selected:
        derived, seeded = build_one(row, args.root, suite, args.mutation_profile)
        derived_rows.append(derived)
        mutations.extend(seeded)
    metadata = {
        "suite": suite,
        "mutation_profile": args.mutation_profile,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "selection_seed": args.seed,
        "selected_repository_count": len(selected),
        "mutation_count": len(mutations),
        "frozen_corpus_modified": False,
    }
    (args.root / "mutation_catalog.json").write_text(json.dumps({"metadata": metadata, "mutations": mutations}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = list(derived_rows[0])
    with (args.root / "derived_manifest.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(derived_rows)
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
