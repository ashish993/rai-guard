"""
Example: FastAPI app with rai-guard middleware.

Run with: uvicorn examples.fastapi_app:app --reload
"""

from fastapi import FastAPI
from pydantic import BaseModel

from raiguard.middleware import AIGuardMiddleware

app = FastAPI(title="My AI App (rai-guard protected)")

# Add rai-guard middleware — inspects all JSON request/response bodies
app.add_middleware(
    AIGuardMiddleware,
    block_on_fail=True,
    score_threshold=0.7,
)


class PromptRequest(BaseModel):
    prompt: str


class PromptResponse(BaseModel):
    response: str


@app.post("/ask", response_model=PromptResponse)
async def ask(body: PromptRequest) -> PromptResponse:
    # In a real app, call your LLM here:
    # response = await openai_client.chat.completions.create(...)
    response_text = f"Echo (protected): {body.prompt}"
    return PromptResponse(response=response_text)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
