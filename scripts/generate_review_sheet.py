import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "candidates_v3.csv"

OUTPUT = BASE_DIR / "dataset" / "manual_review.csv"


df = pd.read_csv(INPUT)


df.insert(
    0,
    "id",
    range(1, len(df)+1)
)


df["keep"] = ""

df["agent_type"] = ""

df["notes"] = ""


columns = [
    "id",
    "repo",
    "ecosystem",
    "stars",
    "language",
    "url",
    "keep",
    "agent_type",
    "notes"
]


df[columns].to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8"
)


print(
    "Generated:",
    OUTPUT
)

print(
    "Candidates:",
    len(df)
)