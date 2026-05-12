from pydantic import BaseModel, field_validator


class RawIngestRequest(BaseModel):
    source: str
    raw: str

    @field_validator("source", "raw")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty")
        return v
