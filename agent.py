from __future__ import annotations

from typing import Any, Callable

from cerebrus import (
    calculate_risk,
    check_intent_alignment,
    create_intent_anchor,
    create_provenance,
    detect_injection,
    monitor_trajectory,
    policy_engine,
    security_analyzer,
    tool_gate,
)
from llm import plan_action
from tools import execute_tool
from security_runtime import (
    action_fingerprint,
    build_inspected_result,
)


ALLOWED_TOOLS = {
    "browser_search",
    "webpage_open",
    "file_read",
    "file_write",
    "email_read",
    "email_attachment",
    "email_send",
}


def _normalize_llm_action(
    llm_action: dict[str, Any],
    history_len: int,
) -> dict[str, Any] | None:

    if llm_action.get("done"):
        return None

    tool = llm_action.get("tool")
    args = llm_action.get("arguments") or {}

    if tool not in ALLOWED_TOOLS:
        raise ValueError(
            f"Unsupported LLM tool: {tool!r}"
        )

    if not isinstance(args, dict):
        raise ValueError("LLM action arguments must be an object.")

    if tool == "browser_search":
        operation = "search"
        parameters = {
            "query": str(args.get("query") or "")
        }

    elif tool == "webpage_open":
        operation = "open"
        parameters = {
            "url": str(args.get("url") or "")
        }

    elif tool == "file_read":
        operation = "read"
        parameters = {
            "file": str(
                args.get("filename")
                or args.get("file")
                or ""
            )
        }

    elif tool == "file_write":
        operation = "write"
        parameters = {
            "file": str(args.get("file") or ""),
            "content": str(args.get("content") or ""),
        }

    elif tool == "email_read":
        operation = "read"
        parameters = {
            "query": str(args.get("query") or "")
        }

    elif tool == "email_attachment":
        operation = "read_attachment"
        parameters = {
            "email_id": str(
                args.get("email_id") or ""
            )
        }

    else:
        operation = "send"
        parameters = {
            "to": str(args.get("to") or ""),
            "content": str(args.get("content") or ""),
        }

    return {
        "action_id": f"action_{history_len + 1:03d}",
        "tool": tool,
        "operation": operation,
        "parameters": parameters,
        "reason": str(
            llm_action.get("reason") or ""
        ),
        "provenance": "authorized_continuation",
    }


def evaluate_action(
    user_task: str,
    intent_anchor: dict[str, Any],
    action: dict[str, Any],
    action_history: list[dict[str, Any]],
    untrusted_content: str = "",
    content_source: str = "agent",
) -> dict[str, Any]:

    tool = action["tool"]
    operation = action["operation"]
    parameters = action.get("parameters", {})

    # 1. Trajectory analysis
    trajectory = monitor_trajectory(
        user_task=user_task,
        current_action=action,
        action_history=action_history,
        intent_anchor=intent_anchor,
    )

    # 2. Provenance
    if content_source == "user":
        provenance_source = "user"

    elif content_source == "agent":
        provenance_source = "authorized_continuation"

    elif content_source in {
        "webpage",
        "external_content",
        "uploaded_file",
        "external_document",
        "untrusted_tool_output",
        "browser_search",
        "file_read",
        "email_read",
        "email_attachment",
    }:
        provenance_source = "untrusted_tool_output"

    else:
        provenance_source = "unknown"

    injection = detect_injection(
        untrusted_content or action.get("reason", "")
    )

    # If the previous result contains an injection,
    # explicitly classify it as an instruction attempt.
    if injection["detected"] and provenance_source == "untrusted_tool_output":
        content_type = "instruction"
    else:
        content_type = "data"

    provenance = create_provenance(
        source=provenance_source,
        content=untrusted_content,
        trusted=(
            provenance_source == "authorized_continuation"
        ),
        content_type=content_type,
    )

    # 3. Intent alignment
    intent_alignment = check_intent_alignment(
        intent_anchor=intent_anchor,
        tool_name=tool,
        operation=operation,
        arguments=parameters,
    )

    # 4. Sensitive resource detection
    sensitive_resource = False

    if tool == "file_read":
        filename = str(
            parameters.get("file", "")
        ).lower()

        sensitive_markers = (
            "password",
            "credential",
            "secret",
            "private",
            "confidential",
            ".env",
            "api_key",
            "access_token",
            "private_key",
        )

        sensitive_resource = any(
            marker in filename
            for marker in sensitive_markers
        )

    # 5. External communication
    external_communication = (
        tool == "email_send"
    )

    # 6. Security analysis
    security = security_analyzer(
        intent_alignment=intent_alignment,
        injection_result=injection,
        provenance=provenance,
        trajectory_report=trajectory,
        sensitive_resource=sensitive_resource,
        external_communication=external_communication,
    )

    # 7. Risk engine
    risk = calculate_risk(
        user_task=user_task,
        tool_name=tool,
        arguments={
            **parameters,
            "_operation": operation,
        },
        intent_anchor=intent_anchor,
        injection_result=injection,
        provenance=provenance,
        trajectory_report=trajectory,
        security_analyzer=security,
    )

    # 8. Policy
    policy = policy_engine(risk)

    # 9. Final enforcement
    gate = tool_gate(policy)

    return {
        "action": action,
        "trajectory": trajectory,
        "provenance": provenance,
        "injection": injection,
        "intent_alignment": intent_alignment,
        "security_analysis": security,
        "risk": risk,
        "policy": policy,
        "gate": gate,
    }


def run_agent(
    user_task: str,
    max_steps: int = 10,
    event_callback: Callable[
        [dict[str, Any]], None
    ] | None = None,
    untrusted_content: str = "",
    content_source: str = "agent",
) -> dict[str, Any]:
    if not user_task or not user_task.strip():
        raise ValueError(
            "user_task cannot be empty."
        )

    if max_steps < 1 or max_steps > 25:
        raise ValueError(
            "max_steps must be between 1 and 25."
        )

    intent_anchor = create_intent_anchor(
        user_task
    )

    state: dict[str, Any] = {
        "history": [],
        "last_result": None,

        # Actions that Cerebrus has explicitly blocked.
        "blocked_actions": [],

        "completed": False,
        "final_response": None,
    }
    events: list[dict[str, Any]] = []

    # Uploaded files are already supplied by the user.
    # Inspect them directly as untrusted data instead of
    # routing them through the server-side file_read tool.
    if untrusted_content and content_source == "uploaded_file":
        upload_action = {
            "tool": "uploaded_file",
            "operation": "inspect",
            "parameters": {},
        }

        upload_result = build_inspected_result(
            upload_action,
            untrusted_content,
        )

        upload_result["source"] = "uploaded_file"
        state["last_result"] = upload_result

    def emit(
        event_type: str,
        **data: Any,
    ) -> None:
        event = {
            "type": event_type,
            **data,
        }

        events.append(event)

        if event_callback:
            event_callback(event)

    emit(
        "intent_anchor",
        intent_anchor=intent_anchor,
    )

    for step in range(1, max_steps + 1):

        emit(
            "step_started",
            step=step,
        )

        # LLM proposes.
        # It never executes a tool.
        llm_action = plan_action(
            user_task=user_task,
            history=state["history"],
            last_result=state["last_result"],
            blocked_actions=state["blocked_actions"],
        )

        if llm_action.get("done"):

            state["completed"] = True

            state["final_response"] = (
                llm_action.get("final_response")
                or ""
            )

            emit(
                "completed",
                step=step,
                final_response=state["final_response"],
            )

            break

        action = _normalize_llm_action(
            llm_action,
            history_len=len(
                state["history"]
            ),
        )

        if action is None:
            state["completed"] = True

            emit(
                "completed",
                step=step,
                final_response="",
            )

            break

        emit(
            "llm_action",
            step=step,
            action=action,
        )

                # =================================================
        # PREVIOUS SAFE RESULT
        # =================================================

        previous_content = untrusted_content
        previous_source = content_source

        if isinstance(
            state["last_result"],
            dict
        ):

            previous_content = str(
                state["last_result"].get(
                    "content",
                    ""
                )
            )

            previous_source = str(
                state["last_result"].get(
                    "source",
                    "agent"
                )
            )


        # =================================================
        # BLOCKED ACTION PROTECTION
        # =================================================

        fingerprint = action_fingerprint(
            action
        )

        blocked_fingerprints = {
            item["fingerprint"]
            for item in state[
                "blocked_actions"
            ]
        }

        if fingerprint in blocked_fingerprints:

            blocked = {

                "action":
                    action,

                "fingerprint":
                    fingerprint,

                "reason":
                    "Exact action was already "
                    "blocked by Cerebrus."
            }

            state[
                "blocked_actions"
            ].append(
                blocked
            )

            emit(
                "action_blocked",
                step=step,
                security={
                    "gate": {

                        "execute":
                            False,

                        "decision":
                            "BLOCK",

                        "reason":
                            blocked["reason"],
                    },

                    "action":
                        action,
                },
            )

            continue


        # =================================================
        # CEREBRUS SECURITY PIPELINE
        # =================================================

        security = evaluate_action(

            user_task=user_task,

            intent_anchor=intent_anchor,

            action=action,

            action_history=[
                h["action"]
                for h in state[
                    "history"
                ]
            ],

            untrusted_content=
                previous_content,

            content_source=
                previous_source,
        )


        emit(
            "security_decision",

            step=step,

            security=security,
        )


        # =================================================
        # TOOL GATE
        # =================================================

        if not security[
            "gate"
        ][
            "execute"
        ]:

            blocked = {

                "action":
                    action,

                "fingerprint":
                    fingerprint,

                "decision":
                    security[
                        "gate"
                    ][
                        "decision"
                    ],

                "reason":
                    security[
                        "gate"
                    ].get(
                        "reason",
                        "Blocked by policy."
                    ),

                "security":
                    security,
            }

            state[
                "blocked_actions"
            ].append(
                blocked
            )


            # IMPORTANT:
            #
            # DO NOT replace last_result
            # with "Cerebrus blocked this action".
            #
            # The last SAFE result must remain
            # available to the planner.

            state[
                "history"
            ].append({

                "action":
                    action,

                "result":
                    None,

                "decision":
                    "BLOCK",

                "security":
                    security,
            })


            emit(
                "action_blocked",

                step=step,

                security=security,
            )

            continue


        # =================================================
        # ACTUAL TOOL EXECUTION
        # =================================================

        result = execute_tool(
            action
        )


        # =================================================
        # UNTRUSTED RESULT INSPECTION
        # =================================================
        #
        # EVERY tool result is treated as untrusted.
        #
        # It is inspected and sanitized BEFORE
        # the LLM sees it.
        # =================================================

        inspected_result = (
            build_inspected_result(
                action,
                result
            )
        )


        # Only sanitized content is stored
        # as the planner-visible result.

        state[
            "last_result"
        ] = inspected_result


        state[
            "history"
        ].append({

            "action":
                action,

            "result":
                inspected_result,

            "decision":
                "ALLOW",
        })


        emit(
            "tool_executed",

            step=step,

            action=action,

            result=inspected_result,
        )


        # =================================================
        # CONTENT SANITIZATION EVENT
        # =================================================

        if inspected_result[
            "injection_detected"
        ]:

            emit(

                "content_sanitized",

                step=step,

                action=action,

                categories=
                    inspected_result[
                        "injection_categories"
                    ],
            )



    else:

        state["completed"] = False

        emit(
            "max_steps_reached",
            max_steps=max_steps,
        )

    return {
        "user_task": user_task,
        "intent_anchor": intent_anchor,
        "completed": state["completed"],
        "final_response": state["final_response"],
        "steps": len(events),
        "history": state["history"],
        "events": events,
    }
