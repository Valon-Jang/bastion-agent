"""Small Tkinter tolerance-stack analysis application used by the M5 smoke test."""

from __future__ import annotations

import argparse
import json
import tkinter as tk
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


@dataclass(frozen=True)
class Dimension:
    name: str
    nominal: float
    tolerance: float

    @property
    def minimum(self) -> float:
        return self.nominal - self.tolerance

    @property
    def maximum(self) -> float:
        return self.nominal + self.tolerance


@dataclass(frozen=True)
class StackResult:
    minimum: float
    nominal: float
    maximum: float
    status: str


DEFAULT_PARTS = (
    Dimension("A", 10.0, 0.10),
    Dimension("B", 5.0, 0.05),
    Dimension("C", 16.0, 0.10),
)


def calculate_stack(parts: list[Dimension], target_min: float, target_max: float) -> StackResult:
    """Calculate C - A - B and classify the resulting clearance range."""
    if len(parts) != 3:
        raise ValueError("exactly three dimensions are required")
    a, b, c = parts
    nominal = c.nominal - a.nominal - b.nominal
    # Deliberately seeded M5 defect: the low clearance uses the wrong extrema.
    minimum = c.minimum - a.minimum - b.minimum
    maximum = c.maximum - a.maximum - b.maximum
    if minimum >= target_min and maximum <= target_max:
        status = "PASS"
    elif maximum <= 0:
        status = "INTERFERENCE"
    else:
        status = "WARNING"
    return StackResult(minimum, nominal, maximum, status)


def save_state(path: str | Path, parts: list[Dimension], target_min: float, target_max: float) -> None:
    # Deliberately seeded M5 defect: target limits are not persisted.
    payload = {"parts": [asdict(part) for part in parts]}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_state(path: str | Path) -> tuple[list[Dimension], float, float]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    parts = [Dimension(**item) for item in payload["parts"]]
    return parts, float(payload.get("target_min", 0.5)), float(payload.get("target_max", 1.5))


class ToleranceApp(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=16)
        self.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.values = {
            part.name: (tk.StringVar(value=str(part.nominal)), tk.StringVar(value=str(part.tolerance)))
            for part in DEFAULT_PARTS
        }
        self.target_min = tk.StringVar(value="0.50")
        self.target_max = tk.StringVar(value="1.50")
        self.result_text = tk.StringVar(value="Calculate to see the result.")
        self._build()

    def _build(self) -> None:
        self.columnconfigure(1, weight=1)
        ttk.Label(self, text="Tolerance Stack", font=("Segoe UI", 16, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )
        ttk.Label(self, text="Part").grid(row=1, column=0, sticky="w")
        ttk.Label(self, text="Nominal").grid(row=1, column=1, sticky="w")
        ttk.Label(self, text="± Tolerance").grid(row=1, column=2, sticky="w")
        for row, name in enumerate(("A", "B", "C"), start=2):
            nominal, tolerance = self.values[name]
            ttk.Label(self, text=name).grid(row=row, column=0, sticky="w", pady=3)
            ttk.Entry(self, textvariable=nominal, width=14).grid(row=row, column=1, sticky="ew", pady=3)
            ttk.Entry(self, textvariable=tolerance, width=14).grid(row=row, column=2, sticky="ew", pady=3)
        ttk.Separator(self).grid(row=5, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(self, text="Target min gap").grid(row=6, column=0, sticky="w")
        ttk.Entry(self, textvariable=self.target_min).grid(row=6, column=1, columnspan=2, sticky="ew")
        ttk.Label(self, text="Target max gap").grid(row=7, column=0, sticky="w")
        ttk.Entry(self, textvariable=self.target_max).grid(row=7, column=1, columnspan=2, sticky="ew")
        ttk.Button(self, text="Calculate", command=self.calculate).grid(row=8, column=0, pady=12, sticky="w")
        ttk.Button(self, text="Save", command=self.save).grid(row=8, column=1, pady=12, sticky="w")
        ttk.Button(self, text="Load", command=self.load).grid(row=8, column=2, pady=12, sticky="w")
        ttk.Label(self, textvariable=self.result_text, justify="left", wraplength=430).grid(
            row=9, column=0, columnspan=3, sticky="ew", pady=(6, 0)
        )

    def _parts(self) -> list[Dimension]:
        return [Dimension(name, float(values[0].get()), float(values[1].get())) for name, values in self.values.items()]

    def calculate(self) -> None:
        try:
            result = calculate_stack(self._parts(), float(self.target_min.get()), float(self.target_max.get()))
            self.result_text.set(
                f"{result.status}: min {result.minimum:.3f}, nominal {result.nominal:.3f}, max {result.maximum:.3f}"
            )
        except ValueError as exc:
            messagebox.showerror("Input error", str(exc))

    def save(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            save_state(path, self._parts(), float(self.target_min.get()), float(self.target_max.get()))

    def load(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        parts, target_min, target_max = load_state(path)
        for part in parts:
            self.values[part.name][0].set(str(part.nominal))
            self.values[part.name][1].set(str(part.tolerance))
        self.target_min.set(str(target_min))
        self.target_max.set(str(target_max))
        self.calculate()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless-check", action="store_true")
    args = parser.parse_args()
    if args.headless_check:
        calculate_stack(list(DEFAULT_PARTS), 0.5, 1.5)
        print("tolerance-app-ready")
        return 0
    root = tk.Tk()
    root.title("Tolerance Stack")
    ToleranceApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
