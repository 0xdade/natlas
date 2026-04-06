from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class NmapConfig(BaseModel):
    ports: str = "top-100"
    timing_template: int = Field(default=4, ge=0, le=5)
    max_rate: int | None = None
    scripts: list[str] = []


class NucleiConfig(BaseModel):
    templates: list[str] = ["cves"]
    severity: list[Literal["info", "low", "medium", "high", "critical"]] = [
        "high",
        "critical",
    ]
    timeout: int = Field(default=30, gt=0)


class ScreenshotConfig(BaseModel):
    timeout: int = Field(default=30, gt=0)
    full_page: bool = False


class WhatWebConfig(BaseModel):
    aggression: int = Field(default=1, ge=1, le=4)
    timeout: int = Field(default=30, gt=0)
