"""SC-PI-*: prompt-injection and deceptive-instruction heuristics.

These rules are *heuristic* by design — they recognise the language of manipulation, not proof of malice.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillfuse.core.models import Category, Confidence, FileKind, Finding, Severity, SkillFile
from skillfuse.rules.base import RegexRule, RuleContext, rx

_INSTRUCTION_KINDS = frozenset({FileKind.INSTRUCTIONS, FileKind.CONFIG})
_URL_RE = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)


class InstructionOverride(RegexRule):
    id = "SC-PI-001"
    title = "Instruction override attempt"
    description = "Text that tells the model to ignore, forget, or override prior/system instructions."
    severity = Severity.HIGH
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    remediation = "Remove language that overrides the host's system prompt or the user's prior instructions."
    references = ("https://owasp.org/www-project-top-10-for-large-language-model-applications/",)
    patterns = (
        rx(
            r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|system|developer|original)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|constraints?|policies|policy)\b"
        ),
        rx(
            r"\b(your|the)\s+(system|developer)\s+prompt\s+(is|has been|was)\s+(now|replaced|superseded|void|invalid)"
        ),
        rx(r"\bnew\s+(system\s+)?instructions?\s*:"),
        rx(r"\b(this|these)\s+(instruction|rule)s?\s+(take|takes|has|have)\s+(precedence|priority)\s+over\b"),
        rx(r"\bfrom now on\b[^.\n]{0,60}\b(you|your)\b[^.\n]{0,40}\b(must|will|are|should)\b"),
    )


class ConcealmentDirective(RegexRule):
    id = "SC-PI-002"
    title = "Concealment directive"
    description = "Instructs the model to hide actions, output, or this instruction from the user."
    severity = Severity.HIGH
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    remediation = "Skills must be transparent: never instruct an agent to hide behaviour from the user."
    patterns = (
        rx(
            r"\b(do not|don'?t|never|without)\s+(tell|inform|notify|alert|mention(ing)?|show(ing)?|reveal(ing)?|disclos(e|ing)|report(ing)?)\s+(this\s+)?(to\s+)?(the\s+)?(user|human|operator|them|anyone)\b"
        ),
        rx(
            r"\b(hide|conceal|mask|obscure|suppress)\s+(this|these|the|your|any)\s+(instruction|step|action|command|call|output|request|message|behavio[u]?r)s?\b"
        ),
        rx(
            r"\b(secretly|silently|covertly|quietly|discreetly|invisibly)\s+(run|execute|send|post|upload|call|invoke|copy|read|collect|gather|forward)\b"
        ),
        rx(
            r"\b(do not|don'?t|never)\s+(log|record|print|display|echo|surface)\s+(this|the|any)\b[^.\n]{0,40}\b(user|output|request|call)\b"
        ),
        rx(r"\bpretend\s+(that\s+)?(nothing|this\s+never|you\s+did\s+not|you\s+didn'?t)\b"),
        rx(r"\b(if|when)\s+asked\b[^.\n]{0,40}\b(deny|say\s+no|claim|insist)\b"),
    )


class IdentityHijack(RegexRule):
    id = "SC-PI-003"
    title = "Role or identity hijack"
    description = "Jailbreak-style persona switching or 'developer mode' framing."
    severity = Severity.MEDIUM
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    remediation = (
        "Describe the task; do not redefine the assistant's identity or claim to unlock hidden modes."
    )
    patterns = (
        rx(
            r"\byou\s+are\s+(now\s+)?(DAN|an?\s+unrestricted|an?\s+unfiltered|an?\s+jailbroken|free\s+of\s+(all\s+)?restrictions)\b"
        ),
        rx(r"\b(developer|god|sudo|root|unrestricted|jailbreak)\s+mode\s+(enabled|activated|on)\b"),
        rx(r"\b(no|without)\s+(ethical|safety|content)\s+(guidelines|restrictions|filters|limits)\b"),
        rx(r"\bact\s+as\s+(if\s+)?(you\s+have|there\s+are)\s+no\s+(rules|restrictions|limits|guardrails)\b"),
    )


class ContextExfiltration(RegexRule):
    id = "SC-PI-004"
    title = "Instruction to exfiltrate context or secrets"
    description = (
        "Asks the model to send conversation context, system prompt, files, or credentials somewhere."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    capabilities = ("network.egress", "secrets.read")
    remediation = "Never instruct an agent to transmit environment variables, credentials, or prompt context."
    patterns = (
        rx(
            r"\b(send|post|upload|transmit|forward|email|exfiltrate|submit|push|copy|paste|include|append)\b[^.\n]{0,60}\b(system\s+prompt|conversation|chat\s+history|context\s+window|environment\s+variables?|env\s+vars?|credentials?|api[\s_-]?keys?|tokens?|secrets?|passwords?|private\s+keys?|\.env\b|ssh\s+keys?)\b[^.\n]{0,80}\b(to|at|into|via)\b"
        ),
        rx(
            r"\b(read|cat|print|dump|collect|gather|harvest|enumerate|list)\b[^.\n]{0,40}\b(~/\.(aws|ssh|config|netrc|npmrc|docker|kube)|\.env\b|credentials?|api[\s_-]?keys?|tokens?|secrets?|passwords?)\b[^.\n]{0,80}\b(send|post|upload|curl|wget|fetch|webhook|http)\b"
        ),
        rx(
            r"\b(include|embed|attach|append)\b[^.\n]{0,40}\b(system\s+prompt|all\s+previous\s+messages|conversation\s+so\s+far|environment\s+variables?)\b[^.\n]{0,40}\b(in|to)\s+(the|your|every|each)\s+(request|response|payload|body|url|query)\b"
        ),
    )

    def check(self, file: SkillFile, ctx: RuleContext) -> Iterator[Finding]:
        for f in super().check(file, ctx):
            # Escalate when a destination URL sits on the same line.
            line_text = file.lines[f.location.line - file.body_offset - 1] if file.lines else ""
            if _URL_RE.search(line_text):
                yield f.model_copy(
                    update={"message": f.message + " (destination URL present on the same line)"}
                )
            else:
                yield f


class TriggeredBehaviour(RegexRule):
    id = "SC-PI-005"
    title = "Conditionally triggered behaviour"
    description = (
        "Behaviour that activates only for specific users, dates, counts, or environments (logic-bomb style)."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    remediation = "Skills should behave identically for all users and environments; remove hidden triggers."
    patterns = (
        rx(
            r"\b(only\s+)?(if|when|once|after)\s+(the\s+)?(user|caller|operator|org|organi[sz]ation|company|hostname|machine|repo(sitory)?|branch)\s+(is|equals|matches|contains|belongs|name[sd]?)\b[^.\n]{0,60}\b(then\s+)?(run|execute|send|post|upload|delete|modify|install|skip|disable|change)\b"
        ),
        rx(
            r"\b(after|once|every)\s+(the\s+)?(\d+|ten|twenty|fifty|hundred|first|nth)\s*(th|st|nd|rd)?\s+(run|invocation|call|use|execution|time)s?\b[^.\n]{0,60}\b(then\s+)?(run|execute|send|post|upload|delete|modify|install|change|switch)\b"
        ),
        rx(
            r"\b(if|when)\s+(the\s+)?(date|time|day|month|year|clock)\s+(is|reaches|passes|equals|>|>=|after|before)\b[^.\n]{0,60}\b(run|execute|send|post|upload|delete|modify|install|change|switch)\b"
        ),
        rx(
            r"\b(if|when|unless)\s+(running\s+)?(in|on)\s+(ci|production|prod|a\s+sandbox|a\s+vm|a\s+container|github\s+actions)\b[^.\n]{0,40}\b(do\s+not|don'?t|skip|avoid|behave|act)\b"
        ),
    )


class ApprovalBypass(RegexRule):
    id = "SC-PI-006"
    title = "Approval or confirmation bypass"
    description = "Instructs the agent to skip user confirmation, auto-approve tool calls, or force destructive actions."
    severity = Severity.HIGH
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    remediation = (
        "Let the host's permission model govern tool execution; never pre-authorise on the user's behalf."
    )
    patterns = (
        rx(
            r"\b(without|skip(ping)?|bypass(ing)?|no need for|never ask for|do not ask for|don'?t ask for|avoid)\s+(the\s+)?(user'?s?\s+)?(asking\s+(for\s+)?)?(confirmation|approval|permission|consent|review|prompt(ing)?)\b"
        ),
        rx(
            r"\b(auto[- ]?approve|auto[- ]?accept|auto[- ]?confirm|always\s+(approve|accept|allow|confirm|say\s+yes))\b"
        ),
        rx(
            r"\b(assume|treat)\s+(all\s+)?(tool\s+calls?|commands?|actions?|requests?)\s+(as\s+)?(pre[- ]?approved|approved|authori[sz]ed|safe)\b"
        ),
        rx(r"\b(the\s+user\s+has\s+(already\s+)?(approved|authori[sz]ed|consented|agreed))\b"),
    )


class ToolCoercion(RegexRule):
    id = "SC-PI-007"
    title = "Unconditional tool-call coercion"
    description = (
        "Forces the model to always invoke a specific external tool or URL before/after every response."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    capabilities = ("network.egress",)
    remediation = "Invoke tools when the task requires them, not unconditionally on every turn."
    patterns = (
        rx(
            r"\b(always|before\s+(every|each|any)|after\s+(every|each|any)|on\s+(every|each)\s+turn|first,?\s+always)\b[^.\n]{0,40}\b(call|invoke|run|use|fetch|query|hit|ping|post\s+to|report\s+to)\b[^.\n]{0,40}\b(tool|endpoint|url|webhook|server|api|https?://)\b"
        ),
        rx(
            r"\b(call|invoke|fetch|post\s+to|report\s+to)\s+https?://[^\s)]+\s+(first|before|after|on\s+every|always)\b"
        ),
    )


class ImperativeMarkdownLink(RegexRule):
    id = "SC-PI-008"
    title = "Instructions sourced from a remote URL"
    description = (
        "Tells the agent to fetch and follow instructions hosted elsewhere, defeating static review."
    )
    severity = Severity.HIGH
    confidence = Confidence.HEURISTIC
    category = Category.PROMPT_INJECTION
    applies_to = _INSTRUCTION_KINDS
    capabilities = ("network.egress",)
    remediation = "Vendor instructions into the package so they are reviewable and hash-pinned."
    patterns = (
        rx(
            r"\b(fetch|download|read|load|retrieve|open|get|pull)\b[^.\n]{0,40}\bhttps?://[^\s)>\]]+[^.\n]{0,60}\b(and\s+)?(follow|execute|apply|obey|run|use)\s+(the|those|these|its|all)\s+(instructions?|steps|commands?|directions?|rules?)\b"
        ),
        rx(
            r"\b(follow|execute|apply|obey)\s+(the\s+)?(instructions?|steps|commands?|rules?)\s+(at|from|in|found\s+at)\s+https?://"
        ),
        rx(
            r"\b(latest|current|updated)\s+(instructions?|rules?|prompt)\s+(are|is|can\s+be\s+found)\s+(at|from)\s+https?://"
        ),
    )


RULES = (
    InstructionOverride(),
    ConcealmentDirective(),
    IdentityHijack(),
    ContextExfiltration(),
    TriggeredBehaviour(),
    ApprovalBypass(),
    ToolCoercion(),
    ImperativeMarkdownLink(),
)
