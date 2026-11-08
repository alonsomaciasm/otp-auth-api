"""Model Context Protocol (MCP) Server for Zero-Trust Adaptive OTP Auth API.

Allows AI Agents to evaluate request risk scores, simulate Proof-of-Work difficulty challenges,
and inspect session and security policies via JSON-RPC 2.0.
"""

import json
from typing import Any, Callable

from app.domain.risk_engine import risk_engine
from app.domain.pow_engine import pow_engine


class FastMCPServer:
    """Lightweight JSON-RPC 2.0 Server for AI Agent Integration."""

    def __init__(self, name: str = "OTPAuthAPI-MCP-Server") -> None:
        self.name = name
        self.tools: dict[str, dict[str, Any]] = {}

    def tool(self, description: str = "") -> Callable:
        def decorator(func: Callable) -> Callable:
            tool_name = func.__name__
            self.tools[tool_name] = {
                "name": tool_name,
                "description": description or func.__doc__ or "",
                "handler": func,
            }
            return func
        return decorator

    async def call_tool(self, tool_name: str, **kwargs: Any) -> str:
        if tool_name not in self.tools:
            return json.dumps({"error": f"Tool '{tool_name}' not found."})
        handler = self.tools[tool_name]["handler"]
        return await handler(**kwargs)

    async def handle_jsonrpc_request(self, request_json: str) -> str:
        try:
            req = json.loads(request_json)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "tools/list":
                tool_list = [
                    {"name": t["name"], "description": t["description"]}
                    for t in self.tools.values()
                ]
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tool_list}})

            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                result_content = await self.call_tool(tool_name, **tool_args)
                return json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": result_content}]},
                })

            return json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})
        except Exception as e:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}})


mcp = FastMCPServer()


@mcp.tool(description="Evaluates context risk using an 8-vector engine and IsolationForest Machine Learning to determine adaptive OTP entropy.")
async def evaluate_risk_profile(
    client_ip: str = "127.0.0.1",
    user_agent: str = "Mozilla/5.0",
    is_new_device: bool = False,
    geo_velocity_alert: bool = False,
    failed_attempts: int = 0
) -> str:
    """Evaluates risk and calculates required OTP entropy and length."""
    policy = risk_engine.get_otp_policy(
        client_ip=client_ip,
        user_agent=user_agent,
        is_new_device=is_new_device,
        geo_velocity_alert=geo_velocity_alert,
        failed_attempts_count=failed_attempts,
    )
    return json.dumps({
        "risk_score": round(policy.risk_score, 2),
        "risk_level": policy.risk_level,
        "otp_type": policy.otp_type,
        "length": policy.length,
        "entropy_bits": round(policy.entropy_bits, 2),
        "ttl_seconds": policy.ttl_seconds,
        "requires_2fa_password": policy.requires_2fa_password,
        "factors": policy.risk_factors,
    }, separators=(",", ":"))


@mcp.tool(description="Generates a dynamic cryptographic Proof-of-Work (PoW) client challenge based on system threat level.")
async def generate_pow_challenge(difficulty_bits: int = 16) -> str:
    """Generates a dynamic SHA-256 Proof-of-Work puzzle for bot and DoS mitigation."""
    challenge_token, nonce, bits = pow_engine.generate_challenge(difficulty_bits=difficulty_bits)
    return json.dumps({
        "challenge_token": challenge_token,
        "difficulty_bits": bits,
    }, separators=(",", ":"))


if __name__ == "__main__":
    print(f"⚡ FastMCP Server '{mcp.name}' running on stdio JSON-RPC 2.0...")
