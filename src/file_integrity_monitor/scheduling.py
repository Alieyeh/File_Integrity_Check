from __future__ import annotations

from datetime import date, datetime, time, timedelta


WEEKDAYS = {
    "monday": 0,
    "mon": 0,
    "tuesday": 1,
    "tue": 1,
    "wednesday": 2,
    "wed": 2,
    "thursday": 3,
    "thu": 3,
    "friday": 4,
    "fri": 4,
    "saturday": 5,
    "sat": 5,
    "sunday": 6,
    "sun": 6,
}


def parse_weekday(value: str) -> int:
    """Parse a full or abbreviated weekday name into Python's weekday index."""

    try:
        return WEEKDAYS[value.strip().lower()]
    except KeyError as exc:
        allowed = ", ".join(("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"))
        raise ValueError(f"Weekday must be one of: {allowed}") from exc


def parse_time_of_day(value: str) -> time:
    """Parse a strict 24-hour HH:MM local time."""

    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError("Time must use HH:MM in 24-hour format.")

    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        raise ValueError("Time must use HH:MM in 24-hour format.") from exc

    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError("Time must use HH:MM in 24-hour format.")
    return time(hour=hour, minute=minute)


def next_weekly_run(now: datetime, *, weekday: int, at_time: time) -> datetime:
    """Calculate the next weekly occurrence strictly after ``now``."""

    if now.tzinfo is not None:
        target = datetime.combine(date=now.date(), time=at_time, tzinfo=now.tzinfo)
    else:
        target = datetime.combine(date=now.date(), time=at_time)

    days_until = (weekday - now.weekday()) % 7
    target = target + timedelta(days=days_until)
    if target <= now:
        target = target + timedelta(days=7)
    return target
