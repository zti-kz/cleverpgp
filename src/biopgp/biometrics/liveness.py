from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum


class LivenessStage(StrEnum):
    NEUTRAL = "neutral"
    TURN = "turn"
    RETURN = "return"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(slots=True)
class HeadTurnLiveness:
    """Active liveness challenge that requires a real change in face geometry."""

    timeout_seconds: float = 25.0
    neutral_limit: float = 0.12
    turn_limit: float = 0.24
    neutral_frames_required: int = 5
    turn_frames_required: int = 3
    return_frames_required: int = 5
    stage: LivenessStage = LivenessStage.NEUTRAL
    consecutive_frames: int = 0
    started_at: float | None = None

    def reset(self) -> None:
        self.stage = LivenessStage.NEUTRAL
        self.consecutive_frames = 0
        self.started_at = None

    def update(
        self, yaw_ratio: float | None, usable: bool, now: float | None = None
    ) -> LivenessStage:
        current_time = time.monotonic() if now is None else now
        if self.started_at is None:
            self.started_at = current_time
        if current_time - self.started_at > self.timeout_seconds:
            self.stage = LivenessStage.FAILED
            return self.stage
        if self.stage in (LivenessStage.COMPLETE, LivenessStage.FAILED):
            return self.stage
        if not usable or yaw_ratio is None:
            self.consecutive_frames = 0
            return self.stage

        if self.stage is LivenessStage.NEUTRAL:
            passed = abs(yaw_ratio) <= self.neutral_limit
            required = self.neutral_frames_required
            next_stage = LivenessStage.TURN
        elif self.stage is LivenessStage.TURN:
            passed = abs(yaw_ratio) >= self.turn_limit
            required = self.turn_frames_required
            next_stage = LivenessStage.RETURN
        else:
            passed = abs(yaw_ratio) <= self.neutral_limit
            required = self.return_frames_required
            next_stage = LivenessStage.COMPLETE

        self.consecutive_frames = self.consecutive_frames + 1 if passed else 0
        if self.consecutive_frames >= required:
            self.stage = next_stage
            self.consecutive_frames = 0
        return self.stage

    @property
    def prompt(self) -> str:
        return {
            LivenessStage.NEUTRAL: "Смотрите прямо в камеру",
            LivenessStage.TURN: "Медленно поверните голову в любую сторону",
            LivenessStage.RETURN: "Вернитесь и снова смотрите прямо",
            LivenessStage.COMPLETE: "Проверка движения пройдена",
            LivenessStage.FAILED: "Время проверки истекло",
        }[self.stage]

    @property
    def progress(self) -> int:
        base = {
            LivenessStage.NEUTRAL: 0,
            LivenessStage.TURN: 30,
            LivenessStage.RETURN: 65,
            LivenessStage.COMPLETE: 100,
            LivenessStage.FAILED: 0,
        }[self.stage]
        if self.stage is LivenessStage.NEUTRAL:
            return min(29, base + 29 * self.consecutive_frames // self.neutral_frames_required)
        if self.stage is LivenessStage.TURN:
            return min(64, base + 34 * self.consecutive_frames // self.turn_frames_required)
        if self.stage is LivenessStage.RETURN:
            return min(99, base + 34 * self.consecutive_frames // self.return_frames_required)
        return base
