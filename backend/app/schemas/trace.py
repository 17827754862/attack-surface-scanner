from pydantic import BaseModel


class TraceEntry(BaseModel):
    node_name: str
    tool_name: str = ""
    started_at: str
    finished_at: str
    status: str
    output_summary: str = ""
    error: str | None = None
