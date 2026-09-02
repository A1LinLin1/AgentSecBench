import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "manual_review_v1.csv"

OUTPUT = BASE_DIR / "dataset" / "manual_review_v2.csv"



# Agent 类型规则

AGENT_TYPES = {


"coding_agent":[

    "code",
    "coding",
    "swe",
    "openhands",
    "devin",
    "program",
    "repo"

],


"rag_agent":[

    "rag",
    "knowledge",
    "document",
    "paper",
    "search"

],


"mcp_agent":[

    "mcp"

],


"multi_agent":[

    "multi",
    "crew",
    "swarm",
    "agentverse",
    "autogen"

],


"workflow_agent":[

    "workflow",
    "pipeline",
    "graph"

],


"general_agent":[

    "agent",
    "assistant",
    "copilot"

]

}



# 安全面

SECURITY_SURFACE = {


"filesystem":[

    "file",
    "document",
    "storage",
    "workspace"

],


"command_execution":[

    "shell",
    "terminal",
    "code",
    "execute",
    "devin",
    "swe"

],


"network":[

    "browser",
    "web",
    "api",
    "http"

],


"database":[

    "sql",
    "database",
    "sqlite"

],


"external_tool":[

    "mcp",
    "tool",
    "plugin"

],


"security":[

    "security",
    "cve",
    "pentest",
    "audit"

]

}



# 框架/SDK排除

FRAMEWORKS=[

    "langchain-ai/langchain",
    "langchain-ai/langgraph",
    "microsoft/autogen",
    "crewaiinc/crewai",
    "fastmcp",
    "langgenius/dify",
    "flowiseai/flowise",
    "langflow-ai/langflow"

]



def match_keywords(text, rules):

    result=[]

    for name, keywords in rules.items():

        for kw in keywords:

            if kw in text:

                result.append(name)

                break

    return list(set(result))



def suggest_keep(row):

    repo=row["repo"].lower()

    text=(
        repo
        +" "
        +str(row.get("reason",""))
    ).lower()


    for f in FRAMEWORKS:

        if f.lower() in repo:

            return "no"


    bad=[

        "tutorial",
        "example",
        "course",
        "template",
        "awesome",
        "starter",
        "test"

    ]


    for b in bad:

        if b in text:

            return "review"



    return "review"



def main():


    df=pd.read_csv(INPUT)



    df["agent_category"]=""


    df["security_surface"]=""


    df["suggestion"]=""



    for idx,row in df.iterrows():


        text=(

            str(row["repo"])

        ).lower()



        agents=match_keywords(
            text,
            AGENT_TYPES
        )


        surfaces=match_keywords(
            text,
            SECURITY_SURFACE
        )


        df.loc[
            idx,
            "agent_category"
        ]=";".join(agents)



        df.loc[
            idx,
            "security_surface"
        ]=";".join(surfaces)



        df.loc[
            idx,
            "suggestion"
        ]=suggest_keep(row)



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