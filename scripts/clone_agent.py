import pandas as pd
import subprocess
from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "candidates.csv"

OUTPUT_DIR = BASE_DIR / "dataset" / "repos"



def clone_repo(url, name):

    target = OUTPUT_DIR / name

    if target.exists():
        return True


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
            timeout=120
        )

        return True


    except Exception as e:

        print(
            "Failed:",
            url,
            e
        )

        return False



def main():

    OUTPUT_DIR.mkdir(
        exist_ok=True
    )


    df=pd.read_csv(INPUT)


    for _,row in df.iterrows():

        print(
            "Cloning:",
            row["repo"]
        )


        clone_repo(
            row["url"],
            row["repo"].replace("/","_")
        )



if __name__=="__main__":
    main()