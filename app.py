from __future__ import annotations

import os
import pathlib
import tempfile
from typing import Any

from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    Form,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agent import evaluate_action, run_agent
from cerebrus import create_intent_anchor
from steg_detector import detect_steganography


app = FastAPI(
    title="CEREBRUS Security Backend",
    version="1.0.0",
    description=(
        "Security enforcement layer between an LLM agent and tool execution."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RunRequest(BaseModel):
    task: str = Field(min_length=1, max_length=10000)
    max_steps: int = Field(default=10, ge=1, le=25)


class ActionCheckRequest(BaseModel):
    task: str = Field(min_length=1, max_length=10000)
    tool: str
    operation: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    content: str = ""
    content_source: str = "webpage"


async def extract_uploaded_content(
    file: UploadFile,
) -> str:
    content = await file.read()

    try:
        return content.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:
        return str(content)


async def scan_uploaded_steganography(
    file: UploadFile,
) -> dict[str, Any]:
    """
    Scan supported uploaded image files for concealed
    steganographic content.

    The uploaded bytes are temporarily written to disk
    so the existing steganography detector can inspect
    the actual image structure and LSB stream.

    The file is never executed.
    """

    filename = file.filename or ""
    extension = pathlib.Path(filename).suffix.lower()

    supported_extensions = {
        ".png",
        ".jpg",
        ".jpeg",
        ".bmp",
    }

    # --------------------------------------------------
    # Non-image files
    # --------------------------------------------------
    #
    # The existing steganography detector currently
    # supports image formats only. Do not interfere with
    # the existing CEREBRUS upload pipeline for other
    # file types.
    #

    if extension not in supported_extensions:
        return {
            "scanned": False,
            "supported": False,
            "detected": False,
            "status": "NOT_APPLICABLE",
            "confidence": 0.0,
            "method": None,
            "payload_detected": False,
            "payload_type": None,
            "extracted_payload": "",
            "payload_matches": [],
            "indicators": [],
            "reason": (
                "Steganography inspection is currently "
                "supported for PNG, JPG, JPEG and BMP files."
            ),
        }

    # --------------------------------------------------
    # Read uploaded bytes
    # --------------------------------------------------

    file_bytes = await file.read()

    if not file_bytes:
        return {
            "scanned": True,
            "supported": True,
            "detected": False,
            "status": "EMPTY_FILE",
            "confidence": 0.0,
            "method": None,
            "payload_detected": False,
            "payload_type": None,
            "extracted_payload": "",
            "payload_matches": [],
            "indicators": [],
            "reason": "Uploaded image file is empty.",
        }

    temporary_path = None

    try:
        # --------------------------------------------------
        # Create temporary image for detector
        # --------------------------------------------------

        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
        ) as temporary_file:

            temporary_file.write(file_bytes)
            temporary_path = temporary_file.name

        # --------------------------------------------------
        # Run CEREBRUS steganography detector
        # --------------------------------------------------

        detection_result = detect_steganography(
            temporary_path,
            content_type="uploaded_file",
        )

        # Do not expose the temporary server path
        detection_result["file"] = filename

        detection_result["scanned"] = True
        detection_result["supported"] = True

        return detection_result

    finally:
        # --------------------------------------------------
        # Remove temporary image
        # --------------------------------------------------

        if temporary_path:
            try:
                os.remove(temporary_path)
            except OSError:
                pass


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "cerebrus-backend",
        "llm_provider": "Groq",
        "model": os.getenv(
            "CEREBRUS_MODEL",
            "openai/gpt-oss-120b",
        ),
    }


@app.post("/api/intent")
def intent(request: RunRequest) -> dict[str, Any]:
    return create_intent_anchor(request.task)


@app.post("/api/security/check")
def security_check(
    request: ActionCheckRequest,
) -> dict[str, Any]:
    """
    Evaluate one proposed action without executing it.
    Used by the frontend security dashboard/demo.
    """

    intent_anchor = create_intent_anchor(request.task)

    action = {
        "action_id": "api_check",
        "tool": request.tool,
        "operation": request.operation,
        "parameters": request.parameters,
        "reason": "API security check",
        "provenance": "authorized_continuation",
    }

    return evaluate_action(
        user_task=request.task,
        intent_anchor=intent_anchor,
        action=action,
        action_history=[],
        untrusted_content=request.content,
        content_source=request.content_source,
    )


@app.post("/api/run")
def run(request: RunRequest) -> dict[str, Any]:
    try:
        return run_agent(
            user_task=request.task,
            max_steps=request.max_steps,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Cerebrus backend error: {exc}",
        ) from exc


@app.post("/api/upload-run")
async def upload_run(
    task: str = Form(...),
    file: UploadFile = File(...),
    max_steps: int = Form(10),
) -> dict[str, Any]:

    try:

        # ==================================================
        # SECURITY LAYER 1
        # STEGANOGRAPHY INSPECTION
        # ==================================================

        steganography_result = (
            await scan_uploaded_steganography(file)
        )

        # ==================================================
        # BLOCK SUSPICIOUS STEGANOGRAPHIC CONTENT
        # ==================================================

        if steganography_result.get("detected"):

            return {
                "completed": False,
                "blocked": True,

                "final_response": (
                    "CEREBRUS blocked the uploaded file "
                    "because concealed steganographic "
                    "content containing suspicious "
                    "instruction-like data was detected."
                ),

                "security": {
                    "status": "BLOCKED",
                    "layer": "STEGANOGRAPHY_DETECTION",

                    "reason": (
                        steganography_result.get(
                            "reason",
                            "Suspicious steganographic "
                            "content detected.",
                        )
                    ),

                    "confidence": (
                        steganography_result.get(
                            "confidence",
                            0.0,
                        )
                    ),

                    "method": (
                        steganography_result.get(
                            "method"
                        )
                    ),

                    "payload_detected": (
                        steganography_result.get(
                            "payload_detected",
                            False,
                        )
                    ),

                    "payload_type": (
                        steganography_result.get(
                            "payload_type"
                        )
                    ),

                    "payload_matches": (
                        steganography_result.get(
                            "payload_matches",
                            [],
                        )
                    ),

                    "indicators": (
                        steganography_result.get(
                            "indicators",
                            [],
                        )
                    ),
                },

                "steganography": (
                    steganography_result
                ),

                "uploaded_file": {
                    "filename": file.filename,
                    "security_source": "untrusted_file",
                },
            }

        # ==================================================
        # CLEAN / NON-IMAGE FILE
        # CONTINUE EXISTING CEREBRUS PIPELINE
        # ==================================================

        # The steganography scanner already consumed
        # the UploadFile stream. Reset it before the
        # existing content extraction code reads it.
        await file.seek(0)

        uploaded_content = (
            await extract_uploaded_content(file)
        )

        # --------------------------------------------------
        # EXISTING CEREBRUS AGENT PIPELINE
        # --------------------------------------------------

        result = run_agent(
            user_task=task,
            max_steps=max_steps,
            untrusted_content=uploaded_content,
            content_source="uploaded_file",
        )

        # --------------------------------------------------
        # Preserve existing response and add detector info
        # --------------------------------------------------

        result["steganography"] = (
            steganography_result
        )

        result["uploaded_file"] = {
            "filename": file.filename,
            "content_preview": uploaded_content[:500],
            "security_source": "untrusted_file",
        }

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Upload pipeline failed: {exc}",
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )