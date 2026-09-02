import pandas as pd
from pathlib import Path
import os
import re
from tqdm import tqdm


BASE_DIR = Path(__file__).resolve().parent.parent


INPUT = BASE_DIR / "dataset" / "candidates.csv"

REPO_DIR = BASE_DIR / "dataset" / "repos"

OUTPUT = BASE_DIR / "dataset" / "selected_agents.csv"



# ==========================
# Framework detection rules
# ==========================

FRAMEWORK_RULES = {


    "LangChain": [

        r"from\s+langchain",
        r"import\s+langchain",
        r"AgentExecutor",
        r"create_react_agent",
        r"initialize_agent"

    ],


    "CrewAI": [

        r"from\s+crewai",
        r"import\s+crewai",
        r"\bAgent\(",
        r"\bCrew\(",
        r"\bTask\("

    ],


    "AutoGen": [

        r"import\s+autogen",
        r"from\s+autogen",
        r"AssistantAgent",
        r"UserProxyAgent",
        r"GroupChat"

    ],


    "MCP": [

        r"from\s+mcp",
        r"import\s+mcp",
        r"FastMCP",
        r"mcp\.server",
        r"@.*tool"

    ],


}



# ==========================
# Generic Agent keywords
# ==========================

AGENT_KEYWORDS = [

    "agent",
    "assistant",
    "planner",
    "executor",
    "workflow",
    "autonomous"

]


TOOL_KEYWORDS = [

    "tool",
    "function_call",
    "function calling",
    "api_call"

]


MEMORY_KEYWORDS = [

    "memory",
    "vectorstore",
    "embedding",
    "retriever",
    "retrieval"

]



# ==========================
# Read source code
# ==========================

def read_repo(repo_path):

    code = ""


    skip_dirs = {

        ".git",
        ".github",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",

        "test",
        "tests",
        "testing",

        "example",
        "examples",

        "demo",
        "demos",

        "benchmark",
        "benchmarks",

        "poc",
        "pocs",

        "exploit",
        "exploits",

        "attack",
        "attacks",

        "security",
        "research",

        "redteam",
        "pentest"
    }



    skip_keywords = [

        "test",

        "exploit",

        "payload",

        "scanner",

        "vuln",

        "reverse",

        "malware"

    ]



    allowed_ext = {

        ".py",

        ".md",

        ".yaml",

        ".yml",

        ".toml"

    }



    for root, dirs, files in os.walk(repo_path):


        dirs[:] = [

            d for d in dirs

            if d.lower()
            not in skip_dirs

        ]



        for file in files:


            if Path(file).suffix not in allowed_ext:
                continue



            if any(
                k in file.lower()
                for k in skip_keywords
            ):
                continue



            path = Path(root) / file


            try:

                with open(
                    path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    code += "\n" + f.read()


            except:

                continue



    return code.lower()



# ==========================
# Framework detection
# ==========================


def detect_framework(code):


    result=[]


    for framework,rules in FRAMEWORK_RULES.items():


        for rule in rules:


            if re.search(
                rule.lower(),
                code,
                re.MULTILINE
            ):

                result.append(framework)

                break


    return result



# ==========================
# Score agent project
# ==========================


def analyze_repo(repo_path):


    score=0


    code=read_repo(repo_path)



    frameworks=detect_framework(code)



    # framework

    if frameworks:

        score +=3



    # agent

    if any(
        k in code
        for k in AGENT_KEYWORDS
    ):

        score+=1



    # tool

    if any(
        k in code
        for k in TOOL_KEYWORDS
    ):

        score+=1



    # memory

    if any(
        k in code
        for k in MEMORY_KEYWORDS
    ):

        score+=1



    # workflow

    if (
        "workflow" in code
        or "planner" in code
    ):

        score+=1



    # dependency

    files=os.listdir(repo_path)


    if any(
        f in files
        for f in [
            "requirements.txt",
            "pyproject.toml",
            "setup.py"
        ]
    ):

        score+=1



    return score, frameworks



# ==========================
# Main
# ==========================


def main():


    candidates=pd.read_csv(INPUT)



    selected=[]



    print(
        "Analyzing repositories..."
    )



    for _,row in tqdm(
        candidates.iterrows(),
        total=len(candidates)
    ):


        repo_name=row["repo"].replace(
            "/",
            "_"
        )


        repo_path=REPO_DIR / repo_name



        if not repo_path.exists():

            continue



        score,frameworks=analyze_repo(
            repo_path
        )



        if score>=4:


            item=row.copy()


            item["score"]=score


            item["detected_framework"]=",".join(
                frameworks
            )


            selected.append(item)



    result=pd.DataFrame(
        selected
    )



    result=result.drop_duplicates(
        subset=["repo"]
    )



    result.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8"
    )



    print(
        "\nSelected:",
        len(result)
    )



if __name__=="__main__":

    main()