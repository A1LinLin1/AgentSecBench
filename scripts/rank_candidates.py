import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "candidates_v3.csv"

OUTPUT = BASE_DIR / "dataset" / "ranked_candidates.csv"



# 高价值关键词
AGENT_KEYWORDS = [

    "agent",
    "agents",

    "tool",
    "memory",

    "workflow",

    "rag",

    "assistant",

    "copilot",

    "mcp",

    "browser",

    "planner",

    "crew",

    "autogen",

    "react"

]


# 安全相关
SECURITY_KEYWORDS = [

    "security",

    "audit",

    "pentest",

    "cve",

    "vulnerability",

    "scanner",

    "browser",

    "shell",

    "code",

    "terminal"

]


# 低价值项目
NEGATIVE_KEYWORDS = [

    "tutorial",

    "course",

    "example",

    "demo",

    "awesome",

    "template",

    "test",

    "benchmark",

    "starter",

    "intro"

]



def calculate_score(row):

    score = 0


    text = (
        str(row["repo"])
        + " "
        + str(row.get("description",""))
    ).lower()



    # =====================
    # Agent behavior
    # =====================

    agent_keywords = [

        "agent",
        "tool",
        "memory",
        "planner",
        "workflow",
        "assistant",
        "copilot",
        "rag",
        "handoff",
        "runner"

    ]


    for kw in agent_keywords:

        if kw in text:
            score += 2



    # =====================
    # Security-critical behavior
    # =====================

    security_keywords = [

        "shell",
        "terminal",
        "filesystem",
        "file",
        "browser",
        "database",
        "github",
        "email",
        "api",
        "mcp",
        "code",
        "execute",
        "execution"

    ]


    for kw in security_keywords:

        if kw in text:
            score += 3



    # =====================
    # Framework penalty
    # =====================

    framework_keywords = [

        "langchain-ai/langchain",
        "langchain-ai/langgraph",
        "crewaiinc/crewai",
        "microsoft/autogen",
        "fastmcp",
        "semantic-kernel",
        "langgenius/dify",
        "flowiseai/flowise",
        "langflow-ai/langflow"

    ]


    for kw in framework_keywords:

        if kw in text:

            score -= 10



    # =====================
    # Tutorial penalty
    # =====================

    bad_keywords = [

        "tutorial",
        "course",
        "example",
        "template",
        "starter",
        "demo",
        "test",
        "awesome"

    ]


    for kw in bad_keywords:

        if kw in text:

            score -= 5



    # =====================
    # Stars (small weight)
    # =====================

    stars=int(row["stars"])


    if stars > 10000:

        score +=2

    elif stars >1000:

        score +=1



    return score

def main():


    df = pd.read_csv(INPUT)



    print(
        "Candidates:",
        len(df)
    )



    df["score"] = df.apply(
        calculate_score,
        axis=1
    )



    df = df.sort_values(
        by=[
            "ecosystem",
            "score",
            "stars"
        ],
        ascending=[
            True,
            False,
            False
        ]
    )



    df["rank"] = range(
        1,
        len(df)+1
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



if __name__ == "__main__":

    main()