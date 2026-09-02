import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "manual_review_v2.csv"

OUTPUT = BASE_DIR / "dataset" / "review_queue.csv"



def priority(row):

    score=row["score"]

    surface=str(
        row["security_surface"]
    )


    # 高价值

    if (
        "command_execution" in surface
        or
        "external_tool" in surface
        or
        "security" in surface
    ):
        return "HIGH"


    if score>=8:

        return "HIGH"


    if score>=5:

        return "MEDIUM"


    return "LOW"



def need_analysis(row):


    if row["priority"]=="HIGH":

        return "YES"


    return "OPTIONAL"



def main():

    df=pd.read_csv(INPUT)


    df["priority"]=df.apply(
        priority,
        axis=1
    )


    df["analysis_required"]=df.apply(
        need_analysis,
        axis=1
    )


    df=df.sort_values(
        [
            "priority",
            "score"
        ],
        ascending=[
            True,
            False
        ]
    )


    df.to_csv(
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