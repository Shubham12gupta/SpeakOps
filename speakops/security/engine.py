# Talk your Infra
import re
import json
import yaml
import hashlib
import datetime
from typing import Dict, Any, Optional


# -------------------------------
# CONFIG LOAD
# -------------------------------
def load_config(path: str = "voice.config.yaml") -> Dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ═══════════════════════════════════════════════════════
# STEP 1 — CONTEXT CHECK
# Who is this? Where? When?
# ═══════════════════════════════════════════════════════
def context_check(intent: Dict, config: Dict) -> Dict:
    environment = intent.get("environment", "staging")
    environments = config.get("environments", {})
    env_config = environments.get(environment, {})

    # restricted hours check
    restricted_hours = env_config.get("restricted_hours")
    if restricted_hours:
        now = datetime.datetime.now().strftime("%H:%M")
        start, end = restricted_hours.split("-")
        if not (start <= now <= end):
            raise PermissionError(
                f"Production changes only allowed between {restricted_hours}. "
                f"Current time: {now}"
            )

    return {
        "environment"     : environment,
        "namespace"       : env_config.get("namespace", "default"),
        "restrictions"    : env_config.get("restrictions", False),
        "auto_confirm"    : env_config.get("auto_confirm", True),
        "restricted_hours": restricted_hours,
    }


# ═══════════════════════════════════════════════════════
# STEP 2 — RBAC CHECK
# Is this role allowed to run this operation?
# ═══════════════════════════════════════════════════════
def rbac_check(intent: Dict, config: Dict) -> Dict:
    user_role  = intent.get("user_role", "junior_engineer")
    operation  = intent.get("operation")
    rbac_config = config.get("rbac", {})
    role_def   = rbac_config.get(user_role, {})

    allowed_ops = role_def.get("allowed_operations", [])
    denied_ops  = role_def.get("denied_operations", [])

    # denied list check
    if operation in denied_ops:
        raise PermissionError(
            f"Operation '{operation}' is explicitly denied for role '{user_role}'"
        )

    # allowed list check
    if "*" not in allowed_ops and operation not in allowed_ops:
        raise PermissionError(
            f"Role '{user_role}' does not have access to '{operation}'"
        )

    # require confirm check
    require_confirm_for = role_def.get("require_confirm_for", [])
    role_requires_confirm = operation in require_confirm_for

    return {
        "user_role"           : user_role,
        "access"              : role_def.get("access", "read"),
        "role_requires_confirm": role_requires_confirm,
        "bypass_confirm"      : role_def.get("bypass_confirm", False),
    }


# ═══════════════════════════════════════════════════════
# STEP 3 — RISK SCORING
# How dangerous is this command?
# 0.0 = safe   1.0 = very dangerous
# ═══════════════════════════════════════════════════════

OPERATION_RISK = {
    # read operations — zero risk
    "get_pods"         : 0.0,
    "fetch_logs"       : 0.0,
    "get_resource_usage": 0.0,
    "get_failing_pods" : 0.0,
    "get_events"       : 0.0,
    "get_app_health"   : 0.0,
    "get_out_of_sync"  : 0.0,
    "get_pipeline_status": 0.0,
    "open_dashboard"   : 0.0,
    "fetch_metrics"    : 0.0,
    "get_alerts"       : 0.0,
    "auto_diagnose"    : 0.0,

    # low risk
    "trigger_build"    : 0.2,
    "get_pipeline_status": 0.1,

    # medium risk
    "scale"            : 0.4,
    "rollout_restart"  : 0.5,
    "trigger_deploy"   : 0.5,
    "sync_app"         : 0.4,
    "helm_upgrade"     : 0.6,
    "cancel_pipeline"  : 0.3,

    # high risk
    "rollout_undo"     : 0.7,
    "rollback_app"     : 0.7,
    "helm_rollback"    : 0.7,

    # critical
    "delete_namespace"  : 1.0,
    "delete_pvc"        : 1.0,
    "scale_to_zero"     : 0.9,
}

ENVIRONMENT_MULTIPLIER = {
    "development" : 0.2,
    "dev"         : 0.2,
    "staging"     : 0.5,
    "production"  : 1.0,
    "prod"        : 1.0,
}

def risk_score(intent: Dict, context: Dict) -> Dict:
    operation   = intent.get("operation", "")
    environment = context.get("environment", "staging")
    params      = intent.get("params", {})

    base_risk   = OPERATION_RISK.get(operation, 0.5)
    env_mult    = ENVIRONMENT_MULTIPLIER.get(environment, 0.5)
    final_risk  = round(base_risk * env_mult, 2)

    # extra risk — replicas to 1 or very high
    if "replicas" in params:
        replicas = int(params["replicas"])
        if replicas == 1:
            final_risk = min(final_risk + 0.1, 1.0)
        if replicas >= 15:
            final_risk = min(final_risk + 0.2, 1.0)

    # risk level label
    if final_risk == 0.0:
        level = "none"
    elif final_risk < 0.3:
        level = "low"
    elif final_risk < 0.6:
        level = "medium"
    elif final_risk < 0.8:
        level = "high"
    else:
        level = "critical"

    return {
        "base_risk"  : base_risk,
        "final_risk" : final_risk,
        "risk_level" : level,
    }


# ═══════════════════════════════════════════════════════
# STEP 4 — POLICY CHECK
# Does this violate any safety policies?
# ═══════════════════════════════════════════════════════
def policy_check(intent: Dict, config: Dict, context: Dict) -> Dict:
    operation   = intent.get("operation")
    params      = intent.get("params", {})
    environment = context.get("environment", "staging")
    safety_cfg  = config.get("safety", {})

    violations = []

    # forbidden operations
    forbidden = safety_cfg.get("forbidden_operations", [])
    if operation in forbidden:
        violations.append(f"Operation '{operation}' is permanently forbidden")

    # block in production
    block_in_prod = safety_cfg.get("block_in_production", [])
    if environment in ["production", "prod"] and operation in block_in_prod:
        violations.append(f"Operation '{operation}' is blocked in production")

    # scale to zero check
    if operation == "scale":
        replicas = int(params.get("replicas", 1))
        if replicas == 0:
            violations.append("Scaling to 0 replicas is blocked by policy")

    # max replicas check
    max_replicas = safety_cfg.get("max_replicas_voice", 20)
    if "replicas" in params:
        replicas = int(params["replicas"])
        if replicas > max_replicas:
            violations.append(
                f"Replicas {replicas} exceed voice command max limit of {max_replicas}"
            )

    if violations:
        raise PermissionError("Policy violations: " + " | ".join(violations))

    return {
        "policy_passed"  : True,
        "dry_run_mode"   : safety_cfg.get("dry_run_mode", False),
        "blast_radius_on": safety_cfg.get("blast_radius_check", True),
    }


# ═══════════════════════════════════════════════════════
# STEP 5 — MFA DECISION
# Does this need extra confirmation?
# Based on risk + role + environment
# ═══════════════════════════════════════════════════════
def mfa_decision( intent: Dict, rbac_result: Dict, risk_result: Dict, context: Dict, policy_result: Dict) -> Dict:

    needs_mfa     = False
    mfa_reasons   = []
    auto_confirm  = context.get("auto_confirm", True)
    risk_level    = risk_result.get("risk_level")
    bypass        = rbac_result.get("bypass_confirm", False)
    role_confirm  = rbac_result.get("role_requires_confirm", False)
    intent_confirm = intent.get("needs_confirm", False)

    # dry run — no mfa needed
    if policy_result.get("dry_run_mode"):
        return {
            "needs_mfa" : False,
            "mfa_reasons": ["dry run mode active"],
            "auto_confirm": True,
        }

    # bypass — admin with explicit bypass
    if bypass and risk_level in ["none", "low"]:
        return {
            "needs_mfa"  : False,
            "mfa_reasons": ["bypass granted for low risk"],
            "auto_confirm": True,
        }

    # auto confirm off — always need mfa
    if not auto_confirm:
        needs_mfa = True
        mfa_reasons.append("auto confirm disabled for this environment")

    # role requires confirm
    if role_confirm:
        needs_mfa = True
        mfa_reasons.append(f"role '{rbac_result['user_role']}' requires confirmation")

    # intent config requires confirm
    if intent_confirm:
        needs_mfa = True
        mfa_reasons.append("command config requires confirmation")

    # risk based
    if risk_level in ["high", "critical"]:
        needs_mfa = True
        mfa_reasons.append(f"risk level is {risk_level}")

    return {
        "needs_mfa"  : needs_mfa,
        "mfa_reasons": mfa_reasons,
        "auto_confirm": not needs_mfa,
    }


# ═══════════════════════════════════════════════════════
# STEP 6 — BLAST RADIUS CHECK
# What is the potential impact of this command?
# ═══════════════════════════════════════════════════════
def blast_radius_check(intent: Dict, context: Dict, policy_result: Dict) -> Dict:
    if not policy_result.get("blast_radius_on", True):
        return {"blast_radius": "unknown", "warning": None}

    operation   = intent.get("operation")
    params      = intent.get("params", {})
    environment = context.get("environment", "staging")
    warnings    = []

    # scale impact
    if operation == "scale":
        replicas = int(params.get("replicas", 1))
        if replicas >= 10 and environment in ["production", "prod"]:
            warnings.append(f"Scaling to {replicas} replicas in production — high resource impact")
        if replicas == 1:
            warnings.append("Single replica — no redundancy, any failure = downtime")

    # rollback impact
    if operation in ["rollout_undo", "rollback_app", "helm_rollback"]:
        warnings.append("Rollback will revert all recent changes — verify this is intended")

    # restart impact
    if operation == "rollout_restart":
        warnings.append("Rolling restart will temporarily reduce capacity")

    # deploy impact
    if operation in ["trigger_deploy", "sync_app", "helm_upgrade"]:
        if environment in ["production", "prod"]:
            warnings.append("Deploying to production — ensure all tests passed")

    radius = "none"
    if len(warnings) == 0:
        radius = "none"
    elif len(warnings) == 1:
        radius = "low"
    elif len(warnings) == 2:
        radius = "medium"
    else:
        radius = "high"

    return {
        "blast_radius": radius,
        "warnings"    : warnings,
    }


# ═══════════════════════════════════════════════════════
# STEP 7 — FINAL CONFIRMATION
# Build the final decision object
# ═══════════════════════════════════════════════════════
def final_confirmation(
    intent       : Dict,
    context      : Dict,
    rbac_result  : Dict,
    risk_result  : Dict,
    policy_result: Dict,
    mfa_result   : Dict,
    blast_result : Dict,
) -> Dict:

    # generate request id
    raw = f"{intent['operation']}{intent['user_role']}{datetime.datetime.now().isoformat()}"
    request_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    approved = True
    rejection_reason = None

    # dry run
    if policy_result.get("dry_run_mode"):
        return {
            "approved"        : False,
            "dry_run"         : True,
            "request_id"      : request_id,
            "rejection_reason": "Dry run mode active — command will not execute",
            "preview"         : {
                "connector" : intent.get("connector"),
                "operation" : intent.get("operation"),
                "params"    : intent.get("params"),
                "environment": context.get("environment"),
            }
        }

    # critical risk in production — always reject without mfa
    if (
        risk_result.get("risk_level") == "critical"
        and context.get("environment") in ["production", "prod"]
        and mfa_result.get("needs_mfa")
        and not mfa_result.get("auto_confirm")
    ):
        approved = False
        rejection_reason = "Critical risk operation in production requires explicit voice confirmation"

    return {
        "approved"        : approved,
        "dry_run"         : False,
        "request_id"      : request_id,
        "rejection_reason": rejection_reason,
        "needs_confirmation": mfa_result.get("needs_mfa", False),
        "confirmation_reasons": mfa_result.get("mfa_reasons", []),
        "execution_ready" : approved and not mfa_result.get("needs_mfa", False),
        "summary"         : {
            "connector"   : intent.get("connector"),
            "operation"   : intent.get("operation"),
            "params"      : intent.get("params"),
            "environment" : context.get("environment"),
            "user_role"   : rbac_result.get("user_role"),
            "risk_level"  : risk_result.get("risk_level"),
            "blast_radius": blast_result.get("blast_radius"),
            "warnings"    : blast_result.get("warnings", []),
            "timeout"     : intent.get("timeout", 60),
            "audit"       : intent.get("audit", {}),
        }
    }


# ═══════════════════════════════════════════════════════
# MAIN SECURITY ENGINE
# Orchestrates all 7 steps
# ═══════════════════════════════════════════════════════
def security_check(intent: Dict) -> Dict:
    config = load_config()

    # Step 1 — Context
    context = context_check(intent, config)

    # Step 2 — RBAC
    rbac_result = rbac_check(intent, config)

    # Step 3 — Risk Score
    risk_result = risk_score(intent, context)

    # Step 4 — Policy
    policy_result = policy_check(intent, config, context)

    # Step 5 — MFA Decision
    mfa_result = mfa_decision(intent, rbac_result, risk_result, context, policy_result)

    # Step 6 — Blast Radius
    blast_result = blast_radius_check(intent, context, policy_result)

    # Step 7 — Final Confirmation
    result = final_confirmation(
        intent, context, rbac_result,
        risk_result, policy_result,
        mfa_result, blast_result
    )

    return result


# ═══════════════════════════════════════════════════════
# CLI TEST
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    # mock intent output from intent.py
    mock_intent = {
        "connector"      : "kubernetes",
        "operation"      : "scale",
        "params"         : {"service": "payment", "replicas": 5},
        "confidence"     : 0.95,
        "source"         : "regex",
        "raw_input"      : "scale payment to 5 replicas",
        "matched_intent" : "scale {service} to {replicas} replicas",
        "needs_confirm"  : True,
        "environment"    : "production",
        "user_role"      : "senior_engineer",
        "audit"          : {"log": True, "level": "info"},
        "timeout"        : 60,
    }

    try:
        result = security_check(mock_intent)

        print("\n🛡️   Security Check Result:")
        print(f"    Request ID        : {result['request_id']}")
        print(f"    Approved          : {result['approved']}")
        print(f"    Execution Ready   : {result.get('execution_ready')}")
        print(f"    Needs Confirmation: {result.get('needs_confirmation')}")

        if result.get("confirmation_reasons"):
            print(f"    Confirm Reasons   : {', '.join(result['confirmation_reasons'])}")

        if result.get("rejection_reason"):
            print(f"    Rejected Because  : {result['rejection_reason']}")

        summary = result.get("summary", {})
        print(f"\n    Risk Level        : {summary.get('risk_level')}")
        print(f"    Blast Radius      : {summary.get('blast_radius')}")

        if summary.get("warnings"):
            print(f"    Warnings          :")
            for w in summary["warnings"]:
                print(f"      ⚠️   {w}")

    except PermissionError as e:
        print(f"\n🔒  Blocked: {str(e)}")

    except Exception as e:
        print(f"\n❌  Error: {str(e)}")