import json
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from app.api.mcp_server import mcp

router = APIRouter()

@router.post("/mcp/rpc", tags=["AI Agent MCP"])
async def mcp_rpc_endpoint(request: Request):
    """
    Endpoint JSON-RPC 2.0 para interacción directa de Agentes de Inteligencia Artificial (MCP).
    Permite evaluar vectores de riesgo de contexto y generar desafíos Proof-of-Work.
    """
    body_text = (await request.body()).decode("utf-8")
    response_json = await mcp.handle_jsonrpc_request(body_text)
    return JSONResponse(content=json.loads(response_json), media_type="application/json")

