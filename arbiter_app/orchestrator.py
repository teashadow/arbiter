"""Ядро arbiter — сводит находки, зовёт дешёвую модель за ПРЕДЛОЖЕНием, валидирует КОДОМ.

Контракт rc (общий с фреймворком): 0 — есть валидный план · 1 — модель предложила
несуществующий инструмент (галлюцинация имени) · 2 — проверка НЕ состоялась (нет БД,
пустая БД, нет ключа, нет сети). Fail-safe: неизвестное = не решаем сами, отдаём rc≥1.

🔴 Модель НЕ решает. Она возвращает строку; всё остальное — код: парсинг, валидация
имени против реального списка инструментов, выбор цели, коды возврата.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# 🔴 Реальный список инструментов контура mad-tools. next_tool ОБЯЗАН быть отсюда —
# всё, чего здесь нет, считается галлюцинацией имени и роняет прогон в rc=1.
TOOLS: tuple[str, ...] = (
    "overreach", "ghostwrite", "needler", "mcpx", "spike", "exhaust",
    "collider", "babel", "snare", "shadow", "banshee", "arsenic", "smuggler",
)

# finding-organizer лежит рядом: mad-tools/finding-organizer (пакет fo).
_FO_DIR = Path(__file__).resolve().parents[2] / "finding-organizer"

# Где искать ключ OpenRouter. Значение НИКОГДА не печатаем — только в env-переменную.
_KEY_ENV = "OPENROUTER_API_KEY"
_SECRETS_ENV = Path.home() / ".config" / "mad" / "secrets.env"
_HULY_ENV = Path("/srv/secrets/mad/openrouter_huly.env")

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_DEFAULT_MODEL = "openai/gpt-4o-mini"

# Тип для инъекции ответа модели в тестах: (summary, key, model) -> raw content str.
ModelFn = Callable[[str, str, str], str]


@dataclass(slots=True)
class Result:
    status: str                       # ok | no_db | empty | no_key | call_failed | bad_response | hallucination
    rc: int
    reason: str
    plan: dict[str, Any] | None = field(default=None)
    proposed_tool: str | None = field(default=None)   # что предложила модель (для честного отчёта о галлюцинации)


# ── чтение находок из общей БД ────────────────────────────────────────────────

def load_findings() -> list[Any] | None:
    """Вернуть находки из finding-organizer, либо None если БД недоступна (rc=2)."""
    if not (_FO_DIR / "fo" / "store.py").exists():
        return None
    if str(_FO_DIR) not in sys.path:
        sys.path.insert(0, str(_FO_DIR))
    try:
        from fo.store import list_findings  # type: ignore
    except Exception:
        return None
    try:
        return list_findings()
    except Exception:
        return None


def summarize(findings: list[Any]) -> str:
    """Компактная сводка находок для модели — маленький промпт, бережём ключ Платова."""
    строки = []
    for f in findings[:15]:  # потолок: не гоним большой контекст
        sev = getattr(f, "severity", "?")
        typ = getattr(f, "type", "?")
        tgt = getattr(f, "target", "") or getattr(f, "program", "")
        title = (getattr(f, "title", "") or "")[:80]
        строки.append(f"- severity={sev} type={typ} target={tgt} :: {title}")
    хвост = "" if len(findings) <= 15 else f"\n(…ещё {len(findings) - 15} находок)"
    return "\n".join(строки) + хвост


def pick_target(findings: list[Any]) -> str:
    """Цель по умолчанию — из самой тяжёлой находки (код выбирает, не модель)."""
    порядок = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    лучшая = min(findings, key=lambda f: порядок.get(getattr(f, "severity", "info"), 9))
    return getattr(лучшая, "target", "") or getattr(лучшая, "program", "") or "unknown"


# ── ключ и вызов модели ───────────────────────────────────────────────────────

def read_api_key() -> str | None:
    """Достать ключ OpenRouter в память. Значение не логируем и не возвращаем наружу CLI.

    Порядок: secrets.env (~/.config/mad, читаемый напрямую) → openrouter_huly.env
    (/srv/secrets/mad, под sudo). Возвращаем строку ключа или None.
    """
    # 1) личный secrets.env
    ключ = _grep_key_from_file(_SECRETS_ENV, sudo=False)
    if ключ:
        return ключ
    # 2) ключ Платова под sudo
    ключ = _grep_key_from_file(_HULY_ENV, sudo=True)
    if ключ:
        return ключ
    # 3) уже в окружении?
    return os.environ.get(_KEY_ENV) or None


def _grep_key_from_file(path: Path, *, sudo: bool) -> str | None:
    """Вынуть значение OPENROUTER_API_KEY из env-файла, не печатая его."""
    try:
        if sudo:
            proc = subprocess.run(
                ["sudo", "-n", "cat", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                return None
            текст = proc.stdout
        else:
            if not path.exists():
                return None
            текст = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for line in текст.splitlines():
        line = line.strip()
        if line.startswith(_KEY_ENV + "="):
            val = line.split("=", 1)[1].strip().strip('"').strip("'")
            return val or None
    return None


def call_model(summary: str, key: str, model: str) -> str:
    """Один дешёвый вызов OpenRouter. Возвращает сырой текст ответа модели.

    Бросает исключение при сетевой/HTTP-ошибке — наверху это станет rc=2 (не состоялась).
    """
    import httpx

    system = (
        "You are a security-testing orchestrator. Given a list of findings, propose which "
        "diagnostic probe to run NEXT and why. Respond with ONLY a JSON object of the form "
        '{"next_tool": "<name>", "target": "<target>", "rationale": "<short reason>"}. '
        "next_tool MUST be exactly one of: " + ", ".join(TOOLS) + ". No prose, JSON only."
    )
    user = f"Findings:\n{summary}\n\nPropose the next probe as JSON."
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
        "max_tokens": 200,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    resp = httpx.post(_OPENROUTER_URL, json=payload, headers=headers, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _extract_json(text: str) -> dict[str, Any] | None:
    """Достать JSON-объект из ответа модели (терпим к обёрткам ```json / прозе вокруг)."""
    if not text:
        return None
    t = text.strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        obj = json.loads(t[start : end + 1])
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


# ── главный ход ────────────────────────────────────────────────────────────────

def plan_next(
    *,
    model: str = _DEFAULT_MODEL,
    mock_response: str | None = None,
    model_fn: ModelFn | None = None,
) -> Result:
    """Собрать план следующей пробы. Вся логика вердикта — здесь, в коде."""
    findings = load_findings()
    if findings is None:
        return Result("no_db", 2, "finding-organizer недоступна — проверка не состоялась")
    if not findings:
        return Result("empty", 2, "в БД нет находок — нет данных для решения")

    summary = summarize(findings)
    default_target = pick_target(findings)

    # получаем сырой ответ модели: мок (тест) → инъекция функции (тест) → живой вызов
    if mock_response is not None:
        raw = mock_response
    else:
        key = read_api_key()
        if not key:
            return Result("no_key", 2, "нет ключа OpenRouter — проверка не состоялась")
        try:
            fn = model_fn or call_model
            raw = fn(summary, key, model)
        except Exception as exc:
            # сеть/HTTP/таймаут — не падаем, честный rc=2
            return Result("call_failed", 2, f"вызов модели не состоялся: {type(exc).__name__}")

    obj = _extract_json(raw)
    if obj is None or "next_tool" not in obj:
        return Result("bad_response", 2, "модель не вернула разбираемый план — не состоялась")

    предложено = str(obj.get("next_tool", "")).strip()
    # 🔴 ВЕРДИКТ КОДОМ: имя обязано быть из реального списка. Галлюцинацию отбрасываем.
    if предложено not in TOOLS:
        return Result(
            "hallucination", 1,
            f"модель предложила несуществующий инструмент: {предложено!r}",
            proposed_tool=предложено,
        )

    plan = {
        "next_tool": предложено,
        "target": str(obj.get("target") or default_target),
        "rationale": str(obj.get("rationale") or "")[:500],
    }
    return Result("ok", 0, "план валиден", plan=plan, proposed_tool=предложено)
