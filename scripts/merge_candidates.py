import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


files=[

BASE_DIR/"dataset"/"candidates_v2.csv",

BASE_DIR/"dataset"/"candidates_extra.csv"

]


dfs=[]


for f in files:

    df=pd.read_csv(f)

    dfs.append(df)



result=pd.concat(
    dfs,
    ignore_index=True
)


result=result.drop_duplicates(
    subset=["repo"]
)


result.to_csv(
    BASE_DIR/"dataset"/"candidates_v3.csv",
    index=False
)


print(
    "Total:",
    len(result)
)