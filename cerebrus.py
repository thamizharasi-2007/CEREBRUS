def create_intent_anchor(user_task):
    """
    Create a structured representation of the user's original intent.

    The Intent Anchor defines the scope of the user's request:
    - what the user wants to accomplish
    - which tools are relevant
    - which operations are allowed
    - which resources are protected
    - whether external communication was requested
    """

    task = user_task.lower()

    anchor = {
        "user_task": user_task,

        "purpose": "general_task",

        "allowed_tools": [],

        "restricted_tools": [],

        "allowed_actions": [],

        "sensitive_data": [
            "confidential.txt",
            "passwords",
            "credentials",
            "api_keys",
            "private_data",
            ".env",
            "secret",
            "secrets",
            "private",
            "config",
            "configuration",
            "access_token",
            "auth_token",
            "private_key"
        ],

        "external_communication": False
    }

    # --------------------------------------------------
    # INFORMATION SEARCH / BROWSING
    # --------------------------------------------------

    if any(word in task for word in [
        "find",
        "search",
        "look for",
        "latest",
        "research",
        "web",
        "browse",
        "browsing",
        "documentation",
        "article",
        "public information",
        "public documentation",
        "public project",
        "public documents",
        "sequence of public project documents",

    ]):

        anchor["purpose"] = "information_retrieval"

        if "browser_search" not in anchor["allowed_tools"]:
            anchor["allowed_tools"].append(
                "browser_search"
            )

        if "webpage_open" not in anchor["allowed_tools"]:
            anchor["allowed_tools"].append(
                "webpage_open"
            )

        anchor["allowed_actions"].extend([
            "search",
            "open"
        ])

    # --------------------------------------------------
    # FILE READING / SUMMARIZATION
    # --------------------------------------------------

    if any(word in task for word in [
        "report",
        "summarize",
        "summary",
        "read",
        "document",
        "file",
        "attachment"
    ]):

        anchor["purpose"] = "information_processing"

        if "file_read" not in anchor["allowed_tools"]:
            anchor["allowed_tools"].append(
                "file_read"
            )

        anchor["allowed_actions"].extend([
            "read",
            "summarize"
        ])

    # --------------------------------------------------
    # FILE CREATION / WRITING
    # --------------------------------------------------

    if any(
       phrase in task
       for phrase in [
           "create a file",
           "write a file",
           "save the summary",
           "save it to",
           "create output",
           "write the summary",
        ]
    ):
        if "file_write" not in anchor["allowed_tools"]:
          anchor["allowed_tools"].append(
            "file_write"
         )

        anchor["allowed_actions"].append(
            "write"
        )

    if any(
        word in task
        for word in [
            "attachment",
            "attachments",
            "attached file",
            "attached document",

        ]
  ):
        if "email_attachment" not in anchor["allowed_tools"]:
           anchor["allowed_tools"].append(
              "email_attachment"
            )

        anchor["allowed_actions"].append(
            "read_attachment"
        )


    # --------------------------------------------------
    # EMAIL READING
    # --------------------------------------------------

    if any(word in task for word in [
        "email",
        "mail",
        "inbox",
        "message",
        "messages"
    ]):

        if "email_read" not in anchor["allowed_tools"]:
            anchor["allowed_tools"].append(
                "email_read"
            )

        anchor["allowed_actions"].extend([
            "read",
            "search",
            "summarize"
        ])

    # --------------------------------------------------
    # EMAIL / EXTERNAL COMMUNICATION
    # --------------------------------------------------

    if (
        "send email" in task
        or "send an email" in task
        or "forward" in task
        or "reply" in task
    ):

        if "email_send" not in anchor["allowed_tools"]:
            anchor["allowed_tools"].append(
                "email_send"
            )

        anchor["allowed_actions"].append(
            "send"
        )

        anchor["external_communication"] = True

    else:

        anchor["restricted_tools"].append(
            "email_send"
        )

    # --------------------------------------------------
    # DEFAULT RESTRICTIONS
    # --------------------------------------------------

    anchor["restricted_tools"].append(
        "sensitive_file_access"
    )

    return anchor

def check_intent_alignment(
    intent_anchor,
    tool_name,
    operation,
    arguments
):
    """
    Compare the agent's proposed action against
    the original user intent.

    Returns:
        HIGH   -> action clearly matches the user's intent
        MEDIUM -> action is uncertain / not clearly justified
        LOW    -> action conflicts with the user's intent
    """

    # --------------------------------------------------
    # 1. CHECK TOOL ALIGNMENT
    # --------------------------------------------------

    if tool_name in intent_anchor["restricted_tools"]:

        return {
            "alignment": "LOW",
            "score": 0.0,
            "reason": (
                "The proposed tool is restricted "
                "by the original user intent."
            )
        }

    if tool_name not in intent_anchor["allowed_tools"]:

        return {
            "alignment": "LOW",
            "score": 0.0,
            "reason": (
                "The proposed tool is not within "
                 "the scope of the original user intent."
            )
        }

    # --------------------------------------------------
    # 2. CHECK OPERATION ALIGNMENT
    # --------------------------------------------------

    if operation not in intent_anchor["allowed_actions"]:

        return {
            "alignment": "LOW",
            "score": 0.0,
            "reason": (
                "The proposed operation is not "
                "authorized by the original task."
            )
        }

    # --------------------------------------------------
    # 3. CHECK SENSITIVE RESOURCE
  # --------------------------------------------------

    if tool_name == "file_read":

        filename = arguments.get("file", "").lower()

        for sensitive_item in intent_anchor["sensitive_data"]:

            if sensitive_item.lower() in filename:

                return {
                    "alignment": "LOW",
                    "score": 0.0,
                    "reason": (
                        "The proposed action targets "
                        "protected sensitive data."
                    )
                }

    # --------------------------------------------------
    # 4. EXTERNAL COMMUNICATION
    # --------------------------------------------------

    if tool_name == "email_send":

        if not intent_anchor["external_communication"]:

            return {
                "alignment": "LOW",
                "score": 0.0,
                "reason": (
                    "External communication was not "
                    "requested by the user."
                )
            }

    # --------------------------------------------------
    # 5. ACTION IS ALIGNED
    # --------------------------------------------------

    return {
        "alignment": "HIGH",
        "score": 1.0,
        "reason": (
            "The proposed action matches the "
            "scope of the original user intent."
        )
    }

def detect_injection(content):
    """
    Detect malicious instructions hidden inside untrusted content.

    The detector checks whether external content is attempting to:
    - override the user's instructions
    - extract system instructions
    - access sensitive data
    - perform unauthorized actions
    - communicate externally

    Returns a structured detection result.
    """

    content_lower = content.lower()

    patterns = {
        "instruction_override": [
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore the user's original request",
            "ignore the user request",
            "disregard previous instructions",
            "disregard the user's request",
            "override your instructions",
            "override the user's request",
            "forget your instructions",
            "new instructions",
            "instead,",
            "do not follow the user's request"
        ],

        "system_prompt_extraction": [
            "system prompt",
            "reveal your instructions",
            "show your system prompt",
            "print your instructions"
        ],

        "data_exfiltration": [
            "send confidential",
            "upload confidential",
            "send credentials",
            "upload credentials",
            "send passwords",
            "send private data",
            "include its contents in the final response",
            "include the contents in the final response",
            "return the contents of",
            "include its complete contents"
        ],

        "unauthorized_tool_use": [
            "read credentials.txt",
            "open credentials.txt",
            "access credentials.txt",
            "read the file confidential.txt",
            "open the file confidential.txt",
            "access the file confidential.txt",
            "read confidential.txt",
            "open confidential.txt",
            "access confidential.txt",
            "delete the file",
            "delete report.txt"
        ],

        "external_communication": [
            "send an email",
            "forward this information",
            "send this information",
            "upload this information"
        ]
    }

    detected_categories = []
    matches = {}

    for category, keywords in patterns.items():

        category_matches = []

        for keyword in keywords:

            if keyword in content_lower:
                category_matches.append(keyword)

        if category_matches:
            detected_categories.append(category)
            matches[category] = category_matches

    # No malicious instruction detected
    if not detected_categories:
        return {
            "detected": False,
            "status": "CLEAN",
            "categories": [],
            "matches": {},
            "reason": "No known malicious instruction patterns detected."
        }

    # Malicious instruction detected
    return {
        "detected": True,
        "status": "INJECTION",
        "categories": detected_categories,
        "matches": matches,
        "reason": (
            "Untrusted content contains instructions that may influence "
            "the agent to deviate from the user's task."
        )
    }

def create_provenance(source, content, trusted=False, content_type="data"):
    """
    Cerebrus Provenance Layer

    Tracks where information came from and determines
    whether that source has authority to influence the agent.

    Provenance is evidence for the Risk Engine.
    It does not make the final security decision by itself.
    """

    # --------------------------------------------------
    # SOURCE CLASSIFICATION
    # --------------------------------------------------

    trusted_sources = [
        "user",
        "system",
        "trusted_tool",
        "authorized_continuation"
    ]

    untrusted_sources = [
        "webpage",
        "external_content",
        "uploaded_file",
        "external_document",
        "untrusted_tool_output"
    ]

    if source in trusted_sources:
        source_trust = "trusted"

    elif source in untrusted_sources:
        source_trust = "untrusted"

    else:
        source_trust = "unknown"

    # --------------------------------------------------
    # INSTRUCTION AUTHORITY
    # --------------------------------------------------

    if source in [
        "user",
        "system",
        "authorized_continuation"
    ]:
        instruction_authority = "authorized"

    else:
        instruction_authority = "not_authorized"

    # --------------------------------------------------
    # CONTENT CLASSIFICATION
    # --------------------------------------------------

    if content_type == "instruction" and instruction_authority == "not_authorized":
        instruction_risk = "high"

    elif content_type == "instruction":
        instruction_risk = "low"

    else:
        instruction_risk = "none"

    # --------------------------------------------------
    # PROVENANCE RECORD
    # --------------------------------------------------

    provenance = {
        "source": source,
        "source_trust": source_trust,
        "trusted": source_trust == "trusted",
        "content_type": content_type,
        "content_length": len(content),

        "instruction_authority": instruction_authority,
        "instruction_risk": instruction_risk
    }

    # --------------------------------------------------
    # CEREBRUS LOG
    # --------------------------------------------------

    print("\n[CEREBRUS PROVENANCE]")
    print("Source:", source)
    print("Source trust:", source_trust)
    print("Content type:", content_type)
    print("Instruction authority:", instruction_authority)
    print("Instruction risk:", instruction_risk)

    return provenance

def check_action(
    user_task,
    tool_name,
    operation,
    arguments,
    content="",
    source="unknown",
    content_type="data"
):
    """
    Cerebrus Security Analysis Layer

    Collects security signals from:
    - Intent Alignment
    - Injection Detection
    - Provenance

    This function does NOT make the final security decision.
    The Risk Engine and Policy Engine will do that.
    """

    print("\n[CEREBRUS SECURITY CHECK]")
    print("User task:", user_task)
    print("Requested tool:", tool_name)
    print("Operation:", operation)

    # --------------------------------------------------
    # 1. CREATE INTENT ANCHOR
    # --------------------------------------------------

    intent_anchor = create_intent_anchor(user_task)

    # --------------------------------------------------
    # 2. CHECK INTENT ALIGNMENT
    # --------------------------------------------------

    intent_alignment = check_intent_alignment(
        intent_anchor,
        tool_name,
        operation,
        arguments
    )

    # --------------------------------------------------
    # 3. DETECT INJECTION
    # --------------------------------------------------

    injection_result = detect_injection(content)

    # --------------------------------------------------
    # 4. CREATE PROVENANCE
    # --------------------------------------------------

    provenance = create_provenance(
        source,
        content,
        content_type=content_type
    )

    # --------------------------------------------------
    # 5. COMBINE SECURITY SIGNALS
    # --------------------------------------------------

    security_analysis = {
        "intent_anchor": intent_anchor,
        "intent_alignment": intent_alignment,
        "injection": injection_result,
        "provenance": provenance
    }

    # --------------------------------------------------
    # CEREBRUS LOG
    # --------------------------------------------------

    print("\n[SECURITY SIGNALS]")

    print(
        "Intent Alignment:",
        intent_alignment["alignment"]
    )

    print(
        "Injection:",
        injection_result["status"]
    )

    print(
        "Provenance:",
        provenance["source_trust"]
    )

    print("\nSecurity analysis completed.")
    print("Final decision will be made by the Risk Engine.")

    return security_analysis


def monitor_trajectory(
    user_task,
    current_action,
    action_history,
    intent_anchor
):
    """
    Cerebrus Trajectory Monitor

    Monitors the agent's behavior across multiple actions.

    Instead of judging only the current action, it evaluates:
    - action history
    - privilege escalation
    - sensitive resource access
    - external communication
    - goal drift
    - suspicious action sequences

    Severity:
        NORMAL
        WARNING
        SUSPICIOUS
        CRITICAL
    """

    print("\n[CEREBRUS TRAJECTORY MONITOR]")

    # ------------------------------------------------
    # 1. Current action information
    # ------------------------------------------------

    current_tool = current_action.get(
        "tool",
        ""
    )

    current_operation = current_action.get(
        "operation",
        ""
    )

    parameters = current_action.get(
        "parameters",
        {}
    )

    print(
        "Current tool:",
        current_tool
    )

    print(
        "Current operation:",
        current_operation
    )

    # ------------------------------------------------
    # 2. Previous action information
    # ------------------------------------------------

    previous_tools = [
        action.get("tool", "")
        for action in action_history
    ]

    trajectory_length = (
        len(action_history) + 1
    )

    reasons = []

    warning_count = 0

    suspicious_count = 0

    critical_count = 0

    # ------------------------------------------------
    # 3. Check sensitive resource access
    # ------------------------------------------------

    sensitive_access = False

    if current_tool == "file_read":

        filename = str(
            parameters.get(
                "file",
                ""
            )
        ).lower()

        sensitive_items = [
         "credentials",
         "credential",
         "password",
         "passwords",
         "api_keys",
         "api_key",
         "private_data",
         "private",
         "confidential",
         ".env",
         "secret",
         "secrets",
         "config",
         "configuration",
         "access_token",
         "auth_token",
         "private_key"
        ]

        for item in sensitive_items:

            if item in filename:

                sensitive_access = True

                suspicious_count += 1

                reasons.append(
                    "Sensitive resource access detected."
                )

                break

    # ------------------------------------------------
    # 4. Check external communication
    # ------------------------------------------------

    external_communication = (
        current_tool == "email_send"
    )

    if external_communication:

        suspicious_count += 1

        reasons.append(
            "External communication action detected."
        )

    # ------------------------------------------------
    # 5. Detect privilege escalation
    # ------------------------------------------------

    allowed_tools = intent_anchor.get(
        "allowed_tools",
        []
    )

    restricted_tools = intent_anchor.get(
        "restricted_tools",
        []
    )

    if current_tool in restricted_tools:

        critical_count += 1

        reasons.append(
            "Action attempts to use a restricted tool."
        )

    elif current_tool not in allowed_tools:

        warning_count += 1

        reasons.append(
            "Action is outside the normal task-scoped tools."
        )

    # ------------------------------------------------
    # 6. Detect sensitive access followed by
    #    external communication
    # ------------------------------------------------

    previous_sensitive_access = False

    for action in action_history:

        tool = action.get(
            "tool",
            ""
        )

        action_parameters = action.get(
            "parameters",
            {}
        )

        if tool == "file_read":

            filename = str(
                action_parameters.get(
                    "file",
                    ""
                )
            ).lower()

            if any(
                item in filename
                for item in [
                   "credentials",
                    "credential",
                    "password",
                    "passwords",
                    "api_keys",
                    "api_key",
                    "private_data",
                    "private",
                    "confidential",
                    ".env",
                    "secret",
                    "secrets",
                    "config",
                    "configuration",
                    "access_token",
                    "auth_token",
                    "private_key"
                ]
            ):

                previous_sensitive_access = True

                break

    if (
        previous_sensitive_access
        and current_tool == "email_send"
    ):

        critical_count += 1

        reasons.append(
            "Sensitive data access was followed "
            "by external communication."
        )

    # ------------------------------------------------
    # 7. Detect search → sensitive access
    # ------------------------------------------------

    if (
        "browser_search" in previous_tools
        and sensitive_access
    ):

        suspicious_count += 1

        reasons.append(
            "Agent escalated from information retrieval "
            "to sensitive resource access."
        )

    # ------------------------------------------------
    # 8. Detect repeated suspicious behavior
    # ------------------------------------------------

    suspicious_tools = [
        "email_send"
    ]

    suspicious_history_count = sum(
        1
        for action in action_history
        if action.get("tool", "")
        in suspicious_tools
    )

    if suspicious_history_count >= 1:

        warning_count += 1

        reasons.append(
            "Previous trajectory already contained "
            "a consequential action."
        )

    # ------------------------------------------------
    # 9. Determine trajectory severity
    # ------------------------------------------------

    if critical_count >= 1:

        trajectory_status = "CRITICAL"

    elif suspicious_count >= 2:

        trajectory_status = "SUSPICIOUS"

    elif suspicious_count == 1:

        trajectory_status = "WARNING"

    elif warning_count >= 1:

        trajectory_status = "WARNING"

    else:

        trajectory_status = "NORMAL"

    # ------------------------------------------------
    # 10. Calculate trajectory risk score
    # ------------------------------------------------

    trajectory_score = (
        critical_count * 40
        + suspicious_count * 20
        + warning_count * 10
    )

    trajectory_score = min(
        trajectory_score,
        100
    )

    # ------------------------------------------------
    # 11. Build trajectory report
    # ------------------------------------------------

    trajectory_report = {

        "trajectory_status":
            trajectory_status,

        "trajectory_score":
            trajectory_score,

        "trajectory_length":
            trajectory_length,

        "current_action":
            current_action,

        "previous_actions":
            action_history.copy(),

        "sensitive_access":
            sensitive_access,

        "external_communication":
            external_communication,

        "privilege_escalation":
            (
                current_tool in restricted_tools
                or current_tool not in allowed_tools
            ),

        "reasons":
            reasons
    }

    # ------------------------------------------------
    # 12. Cerebrus security log
    # ------------------------------------------------

    print(
        "Trajectory Status:",
        trajectory_status
    )

    print(
        "Trajectory Score:",
        trajectory_score
    )

    print(
        "Trajectory Length:",
        trajectory_length
    )

    if reasons:

        print(
            "Trajectory Warnings:"
        )

        for reason in reasons:

            print(
                "-",
                reason
            )

    else:

        print(
            "No suspicious trajectory behavior detected."
        )

    # ------------------------------------------------
    # 13. Return structured result
    # ------------------------------------------------

    return trajectory_report

def security_analyzer(
    intent_alignment,
    injection_result,
    provenance,
    trajectory_report,
    sensitive_resource=False,
    external_communication=False
):
    """
    Cerebrus Security Analyzer

    Combines security signals produced by the
    individual Cerebrus security layers.

    It does not make the final ALLOW/BLOCK decision.
    """

    # -----------------------------
    # Extract security signals
    # -----------------------------

    intent_status = intent_alignment.get(
        "alignment",
        "UNKNOWN"
    )

    injection_status = (
        "DETECTED"
        if injection_result.get("detected", False)
        else "NOT_DETECTED"
    )

    provenance_status = provenance.get(
        "source_trust",
        "unknown"
    ).upper()

    instruction_authority = provenance.get(
    "instruction_authority",
    "unknown"
    ).lower()

    trajectory_status = trajectory_report.get(
        "trajectory_status",
        "NORMAL"
    )

    # -----------------------------
    # Count security violations
    # -----------------------------

    violations = []

    if intent_status == "LOW":
        violations.append(
            "Intent misalignment"
        )

    if injection_status == "DETECTED":
        violations.append(
            "Prompt injection"
        )

    if provenance_status in ["UNTRUSTED", "UNKNOWN"]:
        violations.append("Untrusted or unknown provenance")

    if instruction_authority == "not_authorized":
        violations.append(
           "Unauthorized instruction from untrusted content"
    )

    if trajectory_status in [
        "WARNING",
        "SUSPICIOUS",
        "CRITICAL"
    ]:
        violations.append(
            "Suspicious trajectory"
        )

    if sensitive_resource:
        violations.append(
            "Sensitive resource access"
        )

    if external_communication:
        violations.append(
            "External communication"
        )

    # -----------------------------
    # Classify attack mode
    # -----------------------------

    attack_count = len(violations)

    if attack_count == 0:
        attack_mode = "NONE"
        security_state = "SAFE"

    elif attack_count == 1:
        attack_mode = "SINGLE_ATTACK"
        security_state = "WARNING"

    else:
        attack_mode = "MULTI_ATTACK"
        security_state = "CRITICAL"

    # -----------------------------
    # Build analyzer report
    # -----------------------------

    analysis = {

        "intent_alignment":
            intent_status,

        "injection":
            injection_status,

        "provenance":
            provenance_status,

        "instruction_authority":
            instruction_authority,

        "trajectory":
            trajectory_status,

        "sensitive_resource":
            (
                "DETECTED"
                if sensitive_resource
                else "NONE"
            ),

        "external_communication":
            (
                "DETECTED"
                if external_communication
                else "NONE"
            ),

        "attack_count":
            attack_count,

        "attack_mode":
            attack_mode,

        "security_state":
            security_state,

        "violations":
            violations
    }

    # -----------------------------
    # Cerebrus Security Log
    # -----------------------------

    print("\n[CEREBRUS SECURITY ANALYZER]")

    print(
        "Intent Alignment:",
        intent_status
    )

    print(
        "Injection:",
        injection_status
    )

    print(
        "Provenance:",
        provenance_status
    )

    print(
         "Instruction Authority:",
          instruction_authority.upper()
    )

    print(
        "Trajectory:",
        trajectory_status
    )

    print(
        "Sensitive Resource:",
        (
            "DETECTED"
            if sensitive_resource
            else "NONE"
        )
    )

    print(
        "External Communication:",
        (
            "DETECTED"
            if external_communication
            else "NONE"
        )
    )

    print(
        "Attack Mode:",
        attack_mode
    )

    print(
        "Security State:",
        security_state
    )

    return analysis

def calculate_risk(
    user_task,
    tool_name,
    arguments,
    intent_anchor,
    injection_result,
    provenance,
    trajectory_report=None,
    security_analyzer=None
):
    """
    Cerebrus Risk Engine

    Combines security signals from:
    - user intent
    - tool scope
    - injection detection
    - provenance
    - sensitive data access
    - action sensitivity

    Produces an explainable risk assessment.
    """

    risk_score = 0

    reasons = []

    signals = {}

    # ------------------------------------------------
    # 1. INTENT / TOOL SCOPE
    # ------------------------------------------------

    if tool_name in intent_anchor.get("restricted_tools", []):

        risk_score += 30

        reasons.append(
            "Requested tool is outside the task-scoped privilege."
        )

        intent_risk = 1.0

    elif tool_name not in intent_anchor.get("allowed_tools", []):

        risk_score += 20

        reasons.append(
            "Requested tool is not clearly justified by the original task."
        )

        intent_risk = 0.6

    else:

        intent_risk = 0.0

    signals["intent_risk"] = intent_risk

      # ------------------------------------------------
    # OPERATION / INTENT ALIGNMENT
    # ------------------------------------------------

    requested_operation = arguments.get(
        "_operation",
        ""
    )

    if requested_operation:
        allowed_actions = intent_anchor.get(
            "allowed_actions",
            []
        )

        if requested_operation not in allowed_actions:

            risk_score += 30

            reasons.append(
                "Requested operation is outside "
                "the scope of the original user intent."
            )

            signals["operation_risk"] = 1.0

        else:

            signals["operation_risk"] = 0.0

    else:

        signals["operation_risk"] = 0.0

    # ------------------------------------------------
    # 2. PROVENANCE RISK
    # ------------------------------------------------

    source_trust = provenance.get(
        "source_trust",
        "unknown"
    )

    if source_trust == "untrusted":

        risk_score += 20

        reasons.append(
            "Action was influenced by untrusted external content."
        )

        provenance_risk = 0.8

    elif source_trust == "unknown":

        risk_score += 10

        reasons.append(
            "Content source is unknown."
        )

        provenance_risk = 0.5

    else:

        provenance_risk = 0.0

    signals["provenance_risk"] = provenance_risk

    # ------------------------------------------------
    # UNTRUSTED INSTRUCTION OVERRIDE
    # ------------------------------------------------

    if (
       injection_result.get("detected", False)
       and provenance.get("source_trust")
       == "untrusted"
   ):

       risk_score = 100

       reasons.append(
           "An unauthorized instruction was detected "
           "inside untrusted external content."
        )
       signals["authorization_risk"] = 1.0

    # ------------------------------------------------
    # 3. INJECTION RISK
    # ------------------------------------------------

    if injection_result.get("detected", False):

       risk_score += 50

       reasons.append(
            "Prompt-injection indicators were detected "
            "in untrusted content."
        )
       injection_risk = 1.0

    else:

        injection_risk = 0.0

    signals["injection_risk"] = injection_risk
    # ------------------------------------------------
    # 4. SENSITIVE DATA RISK
    # ------------------------------------------------

    sensitive_data_risk = 0.0

    if tool_name == "file_read":

        filename = str(
            arguments.get("file", "")
        ).lower()

        sensitive_items = [
         "credentials",
         "credential",
         "password",
         "passwords",
         "api_keys",
         "api_key",
         "private_data",
         "private",
         "confidential",
         ".env",
         "secret",
         "secrets",
         "config",
         "configuration",
         "access_token",
         "auth_token",
         "private_key"
        ]

        for item in sensitive_items:

            if item in filename:

                sensitive_data_risk = 1.0

                risk_score += 30

                reasons.append(
                    f"Sensitive data access requested: {filename}"
                )

                break

    signals["data_sensitivity"] = sensitive_data_risk

    # ------------------------------------------------
    # 5. ACTION SENSITIVITY
    # ------------------------------------------------

    if tool_name == "email_send":

        action_sensitivity = 1.0

        risk_score += 20

        reasons.append(
            "External communication is a consequential action."
        )

    elif tool_name == "file_read":

        action_sensitivity = 0.3

    elif tool_name == "browser_search":

        action_sensitivity = 0.1

    else:

        action_sensitivity = 0.5

    signals["action_sensitivity"] = action_sensitivity

    # ------------------------------------------------
    # 6. EXTERNAL COMMUNICATION AUTHORIZATION
    # ------------------------------------------------

    if tool_name == "email_send":

        if not intent_anchor.get(
            "external_communication",
            False
        ):

            risk_score += 25

            reasons.append(
                "External communication was not authorized by the user."
            )
# -----------------------------------------
    # TRAJECTORY RISK
    # -----------------------------------------

    trajectory_risk = 0.0

    if trajectory_report:

        trajectory_status = trajectory_report.get(
            "trajectory_status",
            "NORMAL"
        )

        trajectory_score = trajectory_report.get(
            "trajectory_score",
            0
        )

        if trajectory_status == "CRITICAL":
            trajectory_risk = 1.0
            risk_score += 30
            reasons.append(
                "Agent trajectory shows critical escalation."
            )

        elif trajectory_status == "SUSPICIOUS":
            trajectory_risk = 0.8
            risk_score += 20
            reasons.append(
                "Agent trajectory shows suspicious behavior."
            )

        elif trajectory_status == "WARNING":
            trajectory_risk = 0.4
            risk_score += 10
            reasons.append(
                "Agent trajectory shows warning-level behavior."
            )

        signals["trajectory_risk"] = trajectory_risk
        signals["trajectory_score"] = trajectory_score

    else:

        signals["trajectory_risk"] = 0.0
        signals["trajectory_score"] = 0

    # ------------------------------------------------
    # SECURITY AUTHORIZATION VIOLATION
    # ------------------------------------------------

    if security_analyzer:

        violations = security_analyzer.get(
            "violations",
            []
        )

        if (
            "Unauthorized instruction from untrusted content"
            in violations
        ):

            risk_score = 100

            reasons.append(
                "Unauthorized instruction from untrusted "
                "external content must not execute."
            )

            signals["authorization_risk"] = 1.0

        else:

            signals["authorization_risk"] = 0.0

    else:

        signals["authorization_risk"] = 0.0

    # ------------------------------------------------
    # 7. NORMALIZE
    # ------------------------------------------------

    risk_score = min(
        risk_score,
        100
    )

    # ------------------------------------------------
    # 8. RISK LEVEL
    # ------------------------------------------------

    if risk_score >= 75:

        risk_level = "CRITICAL"

        recommended_control = "BLOCK"

    elif risk_score >= 50:

        risk_level = "HIGH"

        recommended_control = "RESTRICT"

    elif risk_score >= 25:

        risk_level = "MEDIUM"

        recommended_control = "ASK"

    else:

        risk_level = "LOW"

        recommended_control = "ALLOW"

    # ------------------------------------------------
    # 9. BUILD REPORT
    # ------------------------------------------------

    risk_report = {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "signals": signals,

        "reasons": reasons,

        "recommended_control": recommended_control
    }

    # ------------------------------------------------
    # 10. CEREBRUS LOG
    # ------------------------------------------------

    print("\n[CEREBRUS RISK ENGINE]")

    print(
        "Risk Score:",
        risk_score
    )

    print(
        "Risk Level:",
        risk_level
    )

    print(
        "Recommended Control:",
        recommended_control
    )

    if reasons:

        print("Reasons:")

        for reason in reasons:

            print("-", reason)

    return risk_report

def policy_engine(risk_report):
    """
    Convert risk assessment into an enforcement decision.
    """

    risk_level = risk_report.get(
        "risk_level",
        "CRITICAL",
    )

    risk_score = risk_report.get(
        "risk_score",
        100,
    )

    # Fail closed for invalid/unknown states.
    if risk_level == "LOW" and risk_score < 25:

        decision = "ALLOW"

        reason = (
            "Risk is low and the proposed action "
            "is within the task-scoped policy."
        )

    elif risk_level == "MEDIUM":

        decision = "APPROVAL"

        reason = (
            "Risk requires additional approval "
            "before execution."
        )

    elif risk_level == "HIGH":

        decision = "BLOCK"

        reason = (
            "Risk is high and the action is blocked "
            "by the security policy."
        )

    else:

        decision = "BLOCK"

        reason = (
            "Risk is critical or unsafe and the action "
            "must not be executed."
        )

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
    }


def tool_gate(policy_result):
    """
    Cerebrus Tool Gate

    Final enforcement boundary before tool execution.

    The Tool Gate does not calculate risk.
    It only enforces the Policy Engine decision.
    """

    decision = policy_result.get(
        "decision",
        "BLOCK"
    )

    print("\n[CEREBRUS TOOL GATE]")

    if decision == "ALLOW":

        print(
            "Gate Decision: ALLOW"
        )

        return {
            "execute": True,
            "decision": "ALLOW",
            "reason": "Policy allows tool execution."
        }

    elif decision == "APPROVAL":

        print(
            "Gate Decision: APPROVAL REQUIRED"
        )

        return {
            "execute": False,
            "decision": "APPROVAL",
            "reason": (
                "Tool execution is paused "
                "until approval is provided."
            )
        }

    else:

        print(
            "Gate Decision: BLOCK"
        )

        return {
            "execute": False,
            "decision": "BLOCK",
            "reason": (
                "Tool execution is blocked "
                "by the security policy."
            )
        }

def adaptive_control(risk_report, intent_anchor, tool_name):
    """
    Cerebrus Adaptive Control Layer

    Converts the Risk Engine assessment into an action.

    The controller adapts its response according to risk:
        LOW      -> ALLOW
        MEDIUM   -> ASK
        HIGH     -> RESTRICT
        CRITICAL -> BLOCK

    The goal is to stop unsafe actions without unnecessarily
    stopping the legitimate user task.
    """

    risk_score = risk_report.get("risk_score", 0)
    risk_level = risk_report.get("risk_level", "UNKNOWN")

    # --------------------------------------------------
    # CEREBRUS CONTROL DECISION
    # --------------------------------------------------

    if risk_level == "CRITICAL" or risk_score >= 75:

        decision = "BLOCK"

        reason = (
            "Action presents critical risk and must not be executed."
        )

    elif risk_level == "HIGH" or risk_score >= 50:

        decision = "RESTRICT"

        reason = (
            "Action is high risk and should be restricted "
            "while preserving the legitimate task."
        )

    elif risk_level == "MEDIUM" or risk_score >= 25:

        decision = "ASK"

        reason = (
            "Action requires additional user confirmation "
            "before execution."
        )

    else:

        decision = "ALLOW"

        reason = (
            "Action is sufficiently aligned with the "
            "user's task."
        )

    # --------------------------------------------------
    # EXTRA CEREBRUS SAFETY CHECK
    # --------------------------------------------------

    # If the tool is explicitly restricted by the
    # original task, do not allow it simply because
    # the numerical risk score is low.

    if tool_name in intent_anchor.get("restricted_tools", []):

        if decision == "ALLOW":

            decision = "RESTRICT"

            reason = (
                "Tool is outside the task-scoped privilege "
                "defined by the user's original intent."
            )

    # --------------------------------------------------
    # CONTROL RESULT
    # --------------------------------------------------

    control_result = {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "tool": tool_name,
        "reason": reason
    }

    # --------------------------------------------------
    # CEREBRUS LOG
    # --------------------------------------------------

    print("\n[CEREBRUS ADAPTIVE CONTROL]")
    print("Tool:", tool_name)
    print("Risk Level:", risk_level)
    print("Risk Score:", risk_score)
    print("Decision:", decision)
    print("Reason:", reason)

    return control_result
