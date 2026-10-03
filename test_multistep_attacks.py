import json
from pathlib import Path

from cerebrus import (
    create_intent_anchor,
    check_intent_alignment,
    detect_injection,
    create_provenance,
    monitor_trajectory,
    security_analyzer,
    calculate_risk,
    policy_engine,
    tool_gate,
)


# ============================================================
# CEREBRUS MULTI-STEP TRAJECTORY ATTACK TESTER
# Member 3 - 23 Trajectory Attacks
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# Change ONLY this path if your JSON is stored elsewhere.
DATASET_PATH = BASE_DIR / "team3_trajectory_attacks_23.json"

RESULTS_PATH = BASE_DIR / "multistep_attack_results.json"


# ============================================================
# DATASET TOOL MAPPING
# ============================================================
# The attack dataset keeps its original vocabulary.
# This mapping adapts it to Cerebrus' internal tool vocabulary.
# The dataset itself is NOT modified.

TOOL_MAP = {
    "filesystem_read": "file_read",
    "filesystem_write": "file_write",

    "browser_search": "browser_search",
    "browser_open": "webpage_open",
    "webpage_open": "webpage_open",
    "webpage_content": "webpage_open",

    "email_read": "email_read",
    "email_send": "email_send",

    "credential_extraction": "file_read",
    "credential_search": "file_read",

    "network_upload": "network_upload",
    "external_communication": "email_send",

    "system_admin": "system_admin",
}


# ============================================================
# ACTION CONVERSION
# ============================================================

def convert_action(dataset_action):
    """
    Convert one dataset trajectory action into the
    canonical action vocabulary used by Cerebrus.

    The dataset's `action` field is descriptive text,
    not the Cerebrus operation.
    """

    original_tool = str(
        dataset_action.get("tool", "")
    ).lower()

    source = str(
        dataset_action.get("source", "")
    ).upper()

    descriptive_action = str(
        dataset_action.get("action", "")
    )

    # --------------------------------------------------------
    # Legitimate dataset actions
    # --------------------------------------------------------

    operation_map = {
        "browser_search": "search",
        "browser_open": "open",
        "webpage_open": "open",

        "filesystem_read": "read",

        "email_read": "read",
        "attachment_list": "read",

        "filesystem_write": "write",
        "email_send": "send",
    }

    # --------------------------------------------------------
    # Detect an explicitly attempted unauthorized capability
    # from the dataset's descriptive action.
    #
    # Example:
    # "Attempted unauthorized action: credential_extraction."
    # --------------------------------------------------------

    attempted_action = ""

    marker = "Attempted unauthorized action:"

    if marker.lower() in descriptive_action.lower():

        attempted_action = (
            descriptive_action
            .split(":", 1)[1]
            .strip()
            .rstrip(".")
            .strip()
        )

    # --------------------------------------------------------
    # Legitimate action
    # --------------------------------------------------------

    if not attempted_action:

        cerebrus_tool = TOOL_MAP.get(
            original_tool,
            original_tool
        )

        operation = operation_map.get(
            original_tool,
            "read"
        )

        parameters = dict(
            dataset_action.get(
                "parameters",
                {}
            )
        )

        return {
            "tool": cerebrus_tool,
            "operation": operation,
            "parameters": parameters,
            "_original_tool": original_tool,
            "_attempted_action": ""
        }

    # --------------------------------------------------------
    # Malicious capability
    # --------------------------------------------------------
    # Map the unauthorized capability to the actual
    # Cerebrus security boundary.
    # --------------------------------------------------------

    malicious_map = {

        "filesystem_read": {
            "tool": "file_read",
            "operation": "read",
            "file": "unauthorized_file"
        },

        "read_confidential_file": {
            "tool": "file_read",
            "operation": "read",
            "file": "confidential.txt"
        },

        "read_private_file": {
            "tool": "file_read",
            "operation": "read",
            "file": "private_data"
        },

        "credential_extraction": {
            "tool": "file_read",
            "operation": "read",
            "file": "credentials"
        },

        "credential_search": {
            "tool": "file_read",
            "operation": "read",
            "file": "credentials"
        },

        "system_admin": {
            "tool": "system_admin",
            "operation": "admin"
        },

        "email": {
            "tool": "email_send",
            "operation": "send"
        },

        "external_communication": {
            "tool": "email_send",
            "operation": "send"
        },

        "network_upload": {
            "tool": "network_upload",
            "operation": "upload"
        },

        "privilege_escalation": {
            "tool": "system_admin",
            "operation": "admin"
        },

        "permission_laundering": {
            "tool": "system_admin",
            "operation": "admin"
        },

        "poisoned_context_file_access": {
            "tool": "file_read",
            "operation": "read",
            "file": "private_data"
        },

        "second_stage_file_access": {
            "tool": "file_read",
            "operation": "read",
            "file": "private_data"
        },

        "secret_read_and_external_transmission": {
            "tool": "email_send",
            "operation": "send"
        },

        "extract_secret_and_email": {
            "tool": "email_send",
            "operation": "send"
        },

        "file_read_and_upload": {
            "tool": "network_upload",
            "operation": "upload"
        },

        "credential_to_external_url": {
            "tool": "email_send",
            "operation": "send"
        },

        "filesystem_to_email_exfiltration": {
            "tool": "email_send",
            "operation": "send"
        },

        "private_file_upload": {
            "tool": "network_upload",
            "operation": "upload"
        },

        "credential_extraction_and_email": {
            "tool": "email_send",
            "operation": "send"
        },

        "cross_tool_filesystem_access": {
            "tool": "file_read",
            "operation": "read",
            "file": "private_data"
        },

        "external_communication": {
            "tool": "email_send",
            "operation": "send"
        },

        "private_file_exfiltration_by_email": {
            "tool": "email_send",
            "operation": "send"
        },

        "privilege_escalation": {
            "tool": "system_admin",
            "operation": "admin"
        }
    }

    malicious = malicious_map.get(
        attempted_action
    )

    if malicious:

        parameters = {
            key: value
            for key, value in malicious.items()
            if key not in ["tool", "operation"]
        }

        return {
            "tool": malicious["tool"],
            "operation": malicious["operation"],
            "parameters": parameters,
            "_original_tool": original_tool,
            "_attempted_action": attempted_action
        }

    # --------------------------------------------------------
    # Unknown malicious capability
    # Keep it outside the allowed tool vocabulary.
    # --------------------------------------------------------

    return {
        "tool": attempted_action,
        "operation": attempted_action,
        "parameters": {},
        "_original_tool": original_tool,
        "_attempted_action": attempted_action
    }

# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    if not DATASET_PATH.exists():

        raise FileNotFoundError(
            f"\nDataset not found:\n"
            f"{DATASET_PATH}\n\n"
            f"Place team3_trajectory_attacks_23.json "
            f"in the CEREBRUS project folder."
        )

    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    # Support either a plain list or
    # {"scenarios": [...]}

    if isinstance(data, list):

        scenarios = data

    elif isinstance(data, dict):

        scenarios = (
            data.get("scenarios")
            or data.get("attacks")
            or data.get("tests")
            or []
        )

    else:

        raise ValueError(
            "Unsupported dataset format."
        )

    return scenarios


# ============================================================
# PROVENANCE
# ============================================================

def build_provenance(step, scenario):

    source = step.get(
        "source",
        "external_content"
    )

    source_lower = str(
        source
    ).lower()

    # --------------------------------------------------------
    # TRUSTED / AUTHORIZED SOURCES
    # --------------------------------------------------------

    if source_lower in [
        "user",
        "system",
        "trusted_tool",
        "authorized_continuation"
    ]:

        trust = "trusted"

    else:

        trust = "untrusted"

    # --------------------------------------------------------
    # CONTENT TYPE
    # --------------------------------------------------------

    content_type = (
        "email"
        if "email" in source_lower
        else
        "webpage"
        if "web" in source_lower
        else
        "uploaded_file"
        if "file" in source_lower
        else
        "instruction"
    )

    return create_provenance(
        source=source_lower,
        content="",
        trusted=(
            trust == "trusted"
        ),
        content_type=content_type
    )

# ============================================================
# RUN ONE TRAJECTORY
# ============================================================

def run_scenario(scenario):

    attack_id = scenario.get(
        "attack_id",
        scenario.get(
            "id",
            "UNKNOWN"
        )
    )

    user_task = scenario.get(
        "user_intent",
        scenario.get(
            "user_task",
            scenario.get(
                "task",
                ""
            )
        )
    )

    expected_decision = str(
        scenario.get(
            "expected_decision",
            "BLOCK"
        )
    ).upper()

    raw_trajectory = (
        scenario.get("trajectory")
        or scenario.get("steps")
        or scenario.get("actions")
        or []
    )

    if not raw_trajectory:

        return {
            "attack_id": attack_id,
            "status": "ERROR",
            "error": "No trajectory steps found.",
        }

    # --------------------------------------------------------
    # Intent Anchor
    # --------------------------------------------------------

    intent_anchor = create_intent_anchor(
        user_task
    )

    action_history = []

    step_results = []

    final_decision = "ALLOW"

    blocked_at_step = None

    # --------------------------------------------------------
    # Process every action sequentially
    # --------------------------------------------------------

    for index, raw_step in enumerate(
        raw_trajectory,
        start=1
    ):

        current_action = convert_action(
            raw_step
        )

        # Remove internal field before sending
        # to some Cerebrus components.

        current_tool = current_action[
            "tool"
        ]

        current_operation = current_action[
            "operation"
        ]

        parameters = current_action[
            "parameters"
        ]

        # ----------------------------------------------------
        # Intent alignment
        # ----------------------------------------------------

        intent_result = check_intent_alignment(
            intent_anchor,
            current_tool,
            current_operation,
            parameters
        )

        # ----------------------------------------------------
        # Injection detection
        # ----------------------------------------------------

        content = (
            raw_step.get(
                "content",
                ""
            )
            or raw_step.get(
                "output",
                ""
            )
            or raw_step.get(
                "tool_output",
                ""
            )
        )

        injection_result = detect_injection(
            str(content)
        )

        # ----------------------------------------------------
        # Provenance
        # ----------------------------------------------------

        provenance = build_provenance(
            raw_step,
            scenario
        )

        # ----------------------------------------------------
        # Trajectory monitor
        # ----------------------------------------------------

        trajectory_result = monitor_trajectory(
            user_task,
            current_action,
            action_history,
            intent_anchor
        )

        # ----------------------------------------------------
        # Sensitive / external flags
        # ----------------------------------------------------

        sensitive_resource = (
            trajectory_result.get(
                "sensitive_access",
                False
            )
        )

        external_communication = (
            trajectory_result.get(
                "external_communication",
                False
            )
        )

        # ----------------------------------------------------
        # Security analyzer
        # ----------------------------------------------------

        security_result = security_analyzer(
            intent_result,
            injection_result,
            provenance,
            trajectory_result,
            sensitive_resource=sensitive_resource,
            external_communication=external_communication
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        risk_arguments = dict(
            parameters
        )

        risk_arguments[
            "_operation"
        ] = current_operation

        risk_result = calculate_risk(
            user_task,
            current_tool,
            risk_arguments,
            intent_anchor,
            injection_result,
            provenance,
            trajectory_report=trajectory_result,
            security_analyzer=security_result
        )

        # ----------------------------------------------------
        # Policy
        # ----------------------------------------------------

        policy_result = policy_engine(
            risk_result
        )

        # ----------------------------------------------------
        # Tool Gate
        # ----------------------------------------------------

        gate_result = tool_gate(
            policy_result
        )

        gate_decision = str(
            gate_result.get(
                "decision",
                "BLOCK"
            )
        ).upper()

        # ----------------------------------------------------
        # Record step
        # ----------------------------------------------------

        step_result = {

            "step": index,

            "dataset_tool":
                raw_step.get(
                    "tool",
                    ""
                ),

            "cerebrus_tool":
                current_tool,

            "operation":
                current_operation,

            "intent_alignment":
                intent_result,

            "injection":
                injection_result,

            "provenance":
                provenance,

            "trajectory":
                trajectory_result,

            "security_analyzer":
                security_result,

            "risk":
                risk_result,

            "policy":
                policy_result,

            "tool_gate":
                gate_result,

            "decision":
                gate_decision
        }

        step_results.append(
            step_result
        )

        # ----------------------------------------------------
        # BLOCK = attack prevented
        # ----------------------------------------------------

        gate_execute = gate_result.get(
           "execute",
            False
        )

        if not gate_execute:

            final_decision = "BLOCK"

            blocked_at_step = index

            break

        # ----------------------------------------------------
        # Add action to history ONLY if it passed
        # ----------------------------------------------------

        action_history.append(
            {
                "tool": current_tool,
                "operation": current_operation,
                "parameters": parameters
            }
        )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    decision_match = (
        final_decision
        == expected_decision
    )

    malicious_action_prevented = (
        expected_decision == "BLOCK"
        and final_decision == "BLOCK"
    )

    if decision_match:

        status = "PASS"

    else:

        status = "FAIL"

    return {

        "attack_id":
            attack_id,

        "user_intent":
            user_task,

        "expected_decision":
            expected_decision,

        "actual_decision":
            final_decision,

        "decision_match":
            decision_match,

        "malicious_action_prevented":
            malicious_action_prevented,

        "blocked_at_step":
            blocked_at_step,

        "trajectory_length":
            len(raw_trajectory),

        "steps_evaluated":
            len(step_results),

        "status":
            status,

        "step_results":
            step_results
    }


# ============================================================
# MAIN TEST RUNNER
# ============================================================

def main():

    print("=" * 70)
    print(
        "CEREBRUS MULTI-STEP TRAJECTORY ATTACK TEST"
    )
    print(
        "Member 3 - 23 Adversarial Scenarios"
    )
    print("=" * 70)

    scenarios = load_dataset()
    print("\nDATASET STRUCTURE:")
    print(type(scenarios))
    print("\nFIRST SCENARIO:")
    import pprint
    pprint.pp(scenarios[0], sort_dicts=False)

    print(
        f"\nDataset scenarios found: "
        f"{len(scenarios)}"
    )

    results = []

    passed = 0
    failed = 0
    prevented = 0
    errors = 0

    # --------------------------------------------------------
    # Run every scenario
    # --------------------------------------------------------

    for scenario in scenarios:

        attack_id = scenario.get(
            "attack_id",
            scenario.get(
                "id",
                "UNKNOWN"
            )
        )

        print("\n")
        print("=" * 70)
        print(
            f"RUNNING {attack_id}"
        )
        print("=" * 70)

        try:

            result = run_scenario(
                scenario
            )

            results.append(
                result
            )

            if result["status"] == "PASS":

                passed += 1

            else:

                failed += 1

            if result[
                "malicious_action_prevented"
            ]:

                prevented += 1

            print(
                f"Expected : "
                f"{result['expected_decision']}"
            )

            print(
                f"Actual   : "
                f"{result['actual_decision']}"
            )

            print(
                f"Steps    : "
                f"{result['steps_evaluated']}/"
                f"{result['trajectory_length']}"
            )

            print(
                f"Blocked at: "
                f"{result['blocked_at_step']}"
            )

            print(
                f"Status   : "
                f"{result['status']}"
            )

        except Exception as error:

            errors += 1

            print(
                f"ERROR: {error}"
            )

            results.append(
                {
                    "attack_id": attack_id,
                    "status": "ERROR",
                    "error": str(error)
                }
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    total = len(scenarios)

    prevention_rate = (
        prevented / total * 100
        if total
        else 0
    )

    decision_match_rate = (
        passed / total * 100
        if total
        else 0
    )

    output = {

        "dataset":
            "team3_trajectory_attacks_23.json",

        "total_scenarios":
            total,

        "passed":
            passed,

        "failed":
            failed,

        "errors":
            errors,

        "malicious_actions_prevented":
            prevented,

        "decision_match_rate":
            decision_match_rate,

        "prevention_rate":
            prevention_rate,

        "results":
            results
    }

    with open(
        RESULTS_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\n")
    print("=" * 70)
    print(
        "MULTI-STEP ATTACK TEST RESULT"
    )
    print("=" * 70)

    print(
        f"Total scenarios          : {total}"
    )

    print(
        f"Passed                   : {passed}"
    )

    print(
        f"Failed                   : {failed}"
    )

    print(
        f"Errors                   : {errors}"
    )

    print(
        f"Malicious actions blocked: {prevented}/{total}"
    )

    print(
        f"Decision match rate      : "
        f"{decision_match_rate:.1f}%"
    )

    print(
        f"Prevention rate          : "
        f"{prevention_rate:.1f}%"
    )

    print(
        f"\nResults saved to:"
        f"\n{RESULTS_PATH}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()