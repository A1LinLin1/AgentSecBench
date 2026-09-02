import pandas as pd
import subprocess
import json
import hashlib
from pathlib import Path
import time


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "high_priority.csv"

REPO_DIR = BASE_DIR / "dataset" / "repos"

META_DIR = BASE_DIR / "metadata"

META_FILE = META_DIR / "repos.jsonl"



def safe_name(repo):

    return repo.replace(
        "/",
        "_"
    )



def sha256_dir(path):

    sha = hashlib.sha256()

    for file in sorted(path.rglob("*")):

        if file.is_file():

            try:

                sha.update(
                    file.read_bytes()
                )

            except:

                pass


    return sha.hexdigest()



def clone_repo(repo):


    name=safe_name(repo)


    target=REPO_DIR/name


    if target.exists():

        print(
            "Exists:",
            repo
        )

        return target



    url=f"https://github.com/{repo}.git"



    print(
        "Cloning:",
        repo
    )



    try:

        subprocess.run(

            [
                "git",
                "clone",
                "--depth",
                "1",
                url,
                str(target)
            ],

            timeout=300,

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL

        )


        return target


    except Exception as e:


        print(
            "Failed:",
            repo,
            e
        )


        return None




def main():


    REPO_DIR.mkdir(
        exist_ok=True
    )


    META_DIR.mkdir(
        exist_ok=True
    )


    df=pd.read_csv(INPUT)



    with open(
        META_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        for _,row in df.iterrows():


            path=clone_repo(
                row["repo"]
            )


            if path:


                item={


                    "repo":
                    row["repo"],


                    "ecosystem":
                    row["ecosystem"],


                    "stars":
                    int(row["stars"]),


                    "score":
                    int(row["score"]),


                    "local_path":
                    str(path),


                    "sha256":
                    sha256_dir(path)


                }



                f.write(
                    json.dumps(
                        item,
                        ensure_ascii=False
                    )
                    +
                    "\n"
                )


            time.sleep(1)



    print(
        "Finished"
    )



if __name__=="__main__":

    main()