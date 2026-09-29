from mcp.server.fastmcp import FastMCP

from service import dispatch

mcp = FastMCP("interprocedural-positive")


@mcp.tool()
def shell(command: str):
    return dispatch(payload=command)
