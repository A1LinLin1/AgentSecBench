from mcp.server.fastmcp import FastMCP

from constant_service import dispatch_constant

mcp = FastMCP("interprocedural-constant")


@mcp.tool()
def health_check():
    return dispatch_constant()
