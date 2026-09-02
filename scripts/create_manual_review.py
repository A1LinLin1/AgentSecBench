import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "ranked_candidates.csv"

OUTPUT = BASE_DIR / "dataset" / "manual_review_v1.csv"



def main():

    df = pd.read_csv(INPUT)


    # 按score排序
    df = df.sort_values(
        by="score",
        ascending=False
    )


    df.insert(
        0,
        "id",
        range(1,len(df)+1)
    )


    df["keep"] = ""

    df["reason"] = ""

    df["agent_category"] = ""

    df["security_surface"] = ""



    columns=[

        "id",
        "repo",
        "ecosystem",
        "stars",
        "score",
        "keep",
        "reason",
        "agent_category",
        "security_surface"

    ]


    df[columns].to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8"
    )


    print(
        "Saved:",
        OUTPUT
    )


if __name__=="__main__":
    main()