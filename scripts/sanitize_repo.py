from pathlib import Path
import shutil


BASE_DIR = Path(__file__).resolve().parent.parent


REPO_DIR = BASE_DIR / "dataset" / "repos"


SKIP_DIRS = {
    ".git",
    ".github",
    "__pycache__",
    "node_modules",

    "tests",
    "test",
    "testing",

    "examples",
    "example",

    "demo",
    "demos",

    "poc",
    "pocs",

    "exploit",
    "exploits",

    "attack",
    "attacks",

    "research",
    "security",

    "benchmark",
    "benchmarks"
}


SKIP_KEYWORDS = [
    "exploit",
    "payload",
    "reverse_shell",
    "reverseshell",
    "malware",
    "scanner",
    "vuln",
    "pentest"
]


def should_remove(path):

    name = path.name.lower()

    return any(
        k in name
        for k in SKIP_KEYWORDS
    )



def sanitize_repo(repo):

    removed = 0


    for path in repo.rglob("*"):


        if not path.exists():
            continue


        # directory

        if path.is_dir():

            if path.name.lower() in SKIP_DIRS:

                print(
                    "Remove dir:",
                    path
                )

                shutil.rmtree(
                    path,
                    ignore_errors=True
                )

                removed += 1



        else:

            if should_remove(path):

                print(
                    "Remove file:",
                    path
                )

                try:
                    path.unlink()
                    removed += 1

                except:
                    pass


    return removed



def main():

    total = 0


    for repo in REPO_DIR.iterdir():

        if repo.is_dir():

            print(
                "\nSanitize:",
                repo.name
            )

            total += sanitize_repo(repo)


    print(
        "\nRemoved:",
        total
    )


if __name__ == "__main__":
    main()