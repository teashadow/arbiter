"""CLI for arbiter — предложить следующую пробу по общей БД находок.

🔴 Модель ПРЕДЛАГАЕТ, код РЕШАЕТ. Коды возврата: 0 валидный план · 1 модель
предложила несуществующий инструмент · 2 проверка не состоялась (нет БД/ключа/сети).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
from rich.console import Console

from .banner import ARBITER_BANNER
from .orchestrator import TOOLS, plan_next

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{ARBITER_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD LLM-оркестратор над общей БД находок."""


@main.command("tools")
def tools_cmd() -> None:
    """Показать реальный список инструментов, которым доверяет валидатор."""
    console.print("Валидные next_tool (" + str(len(TOOLS)) + "):")
    console.print("  " + ", ".join(TOOLS))


@main.command("next")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить структурный план JSON")
@click.option("--model", default="openai/gpt-4o-mini", show_default=True,
              help="дешёвая модель OpenRouter")
def next_cmd(as_json: str | None, model: str) -> None:
    """Предложить, какую пробу гнать следующей, и почему."""
    # Тестовая инъекция ответа модели (без сети): ARBITER_MOCK_RESPONSE=<raw content>.
    mock = os.environ.get("ARBITER_MOCK_RESPONSE")

    res = plan_next(model=model, mock_response=mock)

    # Всегда пишем машиночитаемый итог, даже когда план не собран — чтобы конвейер видел статус.
    вывод = {
        "status": res.status,
        "rc": res.rc,
        "reason": res.reason,
        "plan": res.plan,
        "proposed_tool": res.proposed_tool,
    }
    if as_json:
        Path(as_json).write_text(json.dumps(вывод, ensure_ascii=False, indent=2), encoding="utf-8")

    if res.rc == 0 and res.plan:
        console.print(f"[green]план[/green]: next_tool=[bold]{res.plan['next_tool']}[/bold] "
                      f"target={res.plan['target']}")
        console.print(f"[dim]почему: {res.plan['rationale']}[/dim]")
    elif res.rc == 1:
        console.print(f"[red]ОТКЛОНЕНО[/red]: {res.reason}")
    else:
        console.print(f"[yellow]НЕ СОСТОЯЛАСЬ[/yellow]: {res.reason}")

    # 🔴 Код возврата — отдельно и последним словом. Различаем 0/1/2.
    raise SystemExit(res.rc)


if __name__ == "__main__":
    main()
