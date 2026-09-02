import requests
import pandas as pd
import time
from tqdm import tqdm
import os

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT = BASE_DIR / "dataset" / "candidates_extra.csv"

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN"
)

QUERIES = {


    # =====================
    # Agent Framework
    # =====================

    "LangChain": [

        "langchain agent language:python",
        "langgraph agent language:python",
        "\"AgentExecutor\" language:python"

    ],


    "CrewAI": [

        "crewai agent language:python",
        "\"from crewai import Agent\""

    ],


    "AutoGen": [

        "autogen agent language:python",
        "\"AssistantAgent\" language:python",
        "ag2 agent language:python"

    ],


    "OpenAI-AgentSDK": [

        "\"from agents import Agent\" language:python",
        "\"from agents import Runner\" language:python",
        "\"function_tool\" language:python"

    ],


    "Semantic-Kernel": [

        "semantic kernel agent language:python",
        "\"KernelFunction\" language:python"

    ],


    "LlamaIndex": [

        "llamaindex agent language:python",
        "\"ReActAgent\" language:python"

    ],



    # =====================
    # MCP
    # =====================

    "MCP": [

        "mcp server python",
        "fastmcp server python",
        "\"@mcp.tool\""

    ],



    # =====================
    # Coding Agent
    # =====================

    "Coding-Agent": [

        "openhands agent",
        "open-devin agent",
        "swe-agent python",
        "aider coding agent"

    ],



    # =====================
    # Autonomous Agent
    # =====================

    "Autonomous-Agent": [

        "autogpt agent",
        "babyagi agent",
        "metagpt agent",
        "superagi agent"

    ],



    # =====================
    # Agent Platform
    # =====================

    "Agent-Platform": [

        "dify agent",
        "flowise agent",
        "langflow agent"

    ],



    # =====================
    # Multi Agent Research
    # =====================

    "Multi-Agent": [

        "camel-ai agent",
        "swarms agent",
        "agentverse"

    ]


}

EXTRA_QUERIES = {


"Coding-Agent": [

    "openhands agent language:python",

    "open-devin agent language:python",

    "swe-agent language:python",

    "aider coding agent"

],



"Autonomous-Agent":[

    "autogpt agent language:python",

    "babyagi agent language:python",

    "metagpt agent language:python",

    "superagi agent language:python"

],



"Agent-Platform":[

    "dify agent workflow",

    "flowise agent",

    "langflow agent"

],



"Multi-Agent":[

    "camel-ai agent",

    "swarms agent python",

    "agentverse"

]

}

def github_search(query, limit=10):

    url = "https://api.github.com/search/repositories"

    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": limit
    }

    headers = {
        "Accept":
        "application/vnd.github+json",
        "Authorization":
        f"Bearer {GITHUB_TOKEN}"
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    r = requests.get(
        url,
        params=params,
        headers=headers
    )

    if r.status_code != 200:
        print(r.text)
        return []

    return r.json()["items"]


def main():

    results = []

    for ecosystem, queries in EXTRA_QUERIES.items():

        print("\nSearching:", ecosystem)

        for q in queries:

            repos = github_search(q)

            for repo in repos:

                results.append({
                    "repo":
                    repo["full_name"],

                    "name":
                    repo["name"],

                    "url":
                    repo["html_url"],

                    "ecosystem":
                    ecosystem,

                    "stars":
                    repo["stargazers_count"],

                    "language":
                    repo["language"],

                    "description":
                    repo["description"]

                })

            time.sleep(1)

    if len(results) == 0:
        print("No Repositories Found.")
        return

    df = pd.DataFrame(results)

    # 去重

    df = df.drop_duplicates(
        subset=["repo"]
    )

    df.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8"
    )

    print(
        "Saved:",
        len(df),
        "repositories"
    )


if __name__ == "__main__":
    main()
