import asyncio
import json
from app.api.mcp_server import mcp, evaluate_risk_profile, generate_pow_challenge

def test_mcp_evaluate_risk():
    res_str = asyncio.run(evaluate_risk_profile(client_ip="192.168.1.10", failed_attempts=0))
    data = json.loads(res_str)
    assert "risk_score" in data
    assert "length" in data
    assert "entropy_bits" in data

def test_mcp_generate_pow():
    res_str = asyncio.run(generate_pow_challenge(difficulty_bits=16))
    data = json.loads(res_str)
    assert data["difficulty_bits"] == 16
    assert "challenge_token" in data

def test_mcp_jsonrpc_tools_list():
    list_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    list_res_str = asyncio.run(mcp.handle_jsonrpc_request(list_req))
    list_res = json.loads(list_res_str)
    assert "result" in list_res
    tools = [t["name"] for t in list_res["result"]["tools"]]
    assert "evaluate_risk_profile" in tools
    assert "generate_pow_challenge" in tools
