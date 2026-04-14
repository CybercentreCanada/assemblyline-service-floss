"""FLOSS service."""

import json
import time
from collections.abc import Iterable
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Any

from assemblyline.common.str_utils import safe_str
from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from rapidfuzz.process import extract

FLOSS = "/opt/floss"


def group_strings(strings: Iterable[str]) -> list[list[str]]:
    """Group strings by similarity.

    Returns:
        A list of similar-string groups.
    """
    # prevent double iteration if strings is a generator
    strings = list(strings)

    groups = []
    choices = set(strings)
    picked = set()
    for string in strings:
        if string in picked:
            continue
        sim_strings = [ls[0] for ls in extract(string, choices, limit=50) if ls[1] > 75]
        for s in sim_strings:
            choices.remove(s)
            picked.add(s)
        if sim_strings:
            groups.append(sim_strings)
    return groups


def ioc_tag(text: bytes, result: ResultSection, just_network: bool = False) -> bool:
    """Tag IOCs found in text to the result section.

    text: text to search for iocs
    result: ResultSection to tag with iocs
    just_network: whether non-network iocs should be skipped

    Returns:
        True if any IOC was found; otherwise, False.
    """
    pattern = PatternMatch()
    ioc = pattern.ioc_match(text, bogon_ip=True, just_network=just_network)
    for kind, values in ioc.items():
        for val in values:
            result.add_tag(kind, val)
    # Return whether any IOCs were found
    return bool(ioc)


def _extract_string(entry: object) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        value = entry.get("string")
        if isinstance(value, str):
            return value
    return None


def _extract_strings(entries: object) -> list[str]:
    if not isinstance(entries, list):
        return []

    strings = []
    for entry in entries:
        string_value = _extract_string(entry)
        if string_value:
            strings.append(string_value)
    return strings


def _extract_static_strings_by_header(entries: object) -> dict[str, list[str]]:
    if not isinstance(entries, list):
        return {}

    sections: dict[str, list[str]] = {}
    for entry in entries:
        if isinstance(entry, str):
            sections.setdefault("FLARE FLOSS Static Strings", []).append(entry)
            continue

        if isinstance(entry, dict):
            string_value = _extract_string(entry)
            if not string_value:
                continue
            encoding = entry.get("encoding")
            if isinstance(encoding, str):
                header = f"FLOSS static {encoding} strings"
            else:
                header = "FLARE FLOSS Static Strings"
            sections.setdefault(header, []).append(string_value)

    return sections


def static_result(header: str, strings: list[str], max_length: int, st_max_size: int) -> ResultSection | None:
    """Generate a ResultSection from FLOSS static strings JSON output.

    Returns:
        A populated result section if relevant IOCs were found, else None.
    """
    result = ResultSection(header, body_format=BODY_FORMAT.MEMORY_DUMP)
    for string in strings:
        line = string.encode(errors="ignore")
        if len(line) > max_length:
            continue
        if ioc_tag(line, result, just_network=len(strings) > st_max_size):
            result.add_line(string)
    return result if result.body else None


def stack_result(strings: list[str]) -> ResultSection | None:
    """Generate a ResultSection from FLOSS stack strings JSON output.

    Returns:
        A populated result section if stack strings exist, else None.
    """
    result = ResultSection("FLARE FLOSS Stacked Strings", body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=Heuristic(3))
    assert result.heuristic

    if not strings:
        return None

    groups = group_strings(strings)
    for group in groups:
        res = ResultSection(
            f"Group: '{min(group, key=len)}' Strings: {len(group)}",
            body="\n".join(group),
            body_format=BODY_FORMAT.MEMORY_DUMP,
        )
        for string in group:
            ioc_tag(string.encode(), res, just_network=len(group) > 1000)
        result.add_subsection(res)

    if any(res.tags for res in result.subsections):
        result.heuristic.add_signature_id("stacked_ioc")

    return result


def format_decoded_body(strings: list[str], score_map: dict[int, float]) -> str:
    """Build a decoded section body with score context and decoded strings.

    Returns:
        A formatted multiline decoded-strings body.
    """
    lines = ["Most likely decoding functions:", "address      score", "---------  -------"]

    for address, score in sorted(score_map.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"0x{address:X}   {score:.5f}")

    lines.append("")
    lines.append(f"FLOSS decoded {len(strings)} strings")
    lines.append("")
    lines.extend(strings)
    return "\n".join(lines)


def extract_decoding_scores(data: dict[str, object]) -> dict[int, float]:
    """Extract decoding function scores from FLOSS JSON output.

    Returns:
        A map of function address to score.
    """
    analysis = data.get("analysis")
    if not isinstance(analysis, dict):
        return {}

    functions = analysis.get("functions")
    if not isinstance(functions, dict):
        return {}

    score_data = functions.get("decoding_function_scores")
    if not isinstance(score_data, dict):
        return {}

    scores: dict[int, float] = {}
    for key, value in score_data.items():
        if not isinstance(value, dict):
            continue
        score = value.get("score")
        if not isinstance(score, (int, float)):
            continue
        try:
            address = int(key)
        except (TypeError, ValueError):
            continue
        scores[address] = float(score)
    return scores


def decoded_result(strings: list[str], body_text: str | None = None) -> ResultSection | None:
    """Generate a ResultSection from FLOSS decoded strings JSON output.

    Returns:
        A populated result section if decoded strings exist, else None.
    """
    if not strings:
        return None

    result = ResultSection("FLARE FLOSS Decoded Strings", body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=Heuristic(1))
    assert result.heuristic
    ioc = False
    for string in strings:
        string_bytes = string.encode(errors="ignore")
        ioc = ioc_tag(string_bytes, result, just_network=len(strings) > 1000) or ioc
        result.add_tag("file.string.decoded", string[:75])
    if ioc:
        result.heuristic.add_signature_id("decoded_ioc")

    result.add_line(body_text if body_text is not None else "\n".join(strings))
    return result


def clean_decoded_strings(decoded_strings: list[str], stack_strings: list[str]) -> list[str]:
    """Reduce noisy decoded strings by preferring stack-aligned values.

    Returns:
        A filtered decoded-string list.
    """
    decoded_unique = list(dict.fromkeys(decoded_strings))
    stack_unique = list(dict.fromkeys(stack_strings))

    if not decoded_unique:
        return []

    if not stack_unique:
        return decoded_unique

    # Keep decoded output unchanged unless it is substantially noisier than stack output.
    if len(decoded_unique) <= len(stack_unique) + 3:
        return decoded_unique

    decoded_set = set(decoded_unique)
    filtered = []
    for stack_string in stack_unique:
        if stack_string in decoded_set:
            filtered.append(stack_string)
            continue

        # Map minor decoded variants back to their closest stable stack string.
        best = extract(stack_string, decoded_unique, limit=1)
        if best and best[0][1] >= 90:
            filtered.append(stack_string)
            continue

        # Accept close matches that differ mainly by repeated-character runs.
        compact_stack = "".join(ch for i, ch in enumerate(stack_string) if i == 0 or ch != stack_string[i - 1])
        for decoded_string in decoded_unique:
            compact_decoded = "".join(
                ch for i, ch in enumerate(decoded_string) if i == 0 or ch != decoded_string[i - 1]
            )
            if compact_decoded == compact_stack:
                filtered.append(stack_string)
                break

    return filtered if filtered else decoded_unique


def parse_floss_json_bytes(output: bytes, logger: Any, source: str) -> dict[str, object]:
    """Load FLOSS JSON output from process stdout bytes.

    Returns:
        The parsed FLOSS JSON document, or an empty dict on failure.
    """
    if not output:
        return {}

    try:
        data = json.loads(output.decode("utf-8", errors="ignore"))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError as err:
        logger.warning(f"Failed to parse FLOSS JSON output from {source}: {err}")
    return {}


class Floss(ServiceBase):
    """Service using the FLARE Obfuscated String Solver.

    see https://github.com/mandiant/flare-floss for documentation
    on the FLOSS tool
    """

    def execute(self, request: ServiceRequest) -> None:
        """Main module see README for details."""
        start = time.time()

        result = Result()
        request.result = result
        file_path = request.file_path
        if request.deep_scan:
            # Maximum size of submitted file to run this service:
            max_size = self.config.get("deep_scan_max_size", 200000)
            # String length maximum, used in basic ASCII and UNICODE modules:
            max_length = self.config.get("deep_scan_max_length", 1000000)
            # String list maximum size
            # List produced by basic ASCII and UNICODE module results and will determine
            # if patterns.py will only evaluate network IOC patterns:
            st_max_size = self.config.get("deep_scan_st_max", 100000)
            # Minimum string size for encoded/stacked string modules:
            enc_min_length = self.config.get("deep_scan_enc_min", 7)
            stack_min_length = self.config.get("deep_scan_stack_min", 7)
        else:
            max_size = self.config.get("max_size", 85000)
            max_length = self.config.get("max_length", 5000)
            st_max_size = self.config.get("st_max_size", 0)
            enc_min_length = self.config.get("enc_min_length", 7)
            stack_min_length = self.config.get("stack_min_length", 7)
        timeout = self.service_attributes.timeout - 50

        if request.file_size > max_size:
            return

        # Run FLOSS once for static/stack strings and once for decoded strings.
        common_args = [FLOSS, "-j", "-q"]
        stack_args = common_args + ["-n", str(stack_min_length), "--no", "decoded", "--no", "tight", "--", file_path]

        decode_args = common_args + ["-n", str(enc_min_length), "--only", "decoded", "--", file_path]

        with (
            Popen(stack_args, stdout=PIPE, stderr=PIPE) as stack,
            Popen(decode_args, stdout=PIPE, stderr=PIPE) as decode,
        ):
            # Stack/static extraction run.
            stack_out, _, timed_out = self.handle_process(stack, timeout + start - time.time(), " ".join(stack_args))
            if timed_out:
                result.add_section(ResultSection("FLARE FLOSS stacked strings timed out"))
                self.log.warning(f"floss stacked strings timed out for sample {request.sha256}")

            # Decoded extraction run.
            dec_out, dec_err, timed_out = self.handle_process(
                decode, timeout + start - time.time(), " ".join(decode_args)
            )
            if timed_out:
                result.add_section(ResultSection("FLARE FLOSS decoded strings timed out"))
                self.log.warning(f"floss decoded strings timed out for sample {request.sha256}")

        # Parse FLOSS JSON documents from each run.
        stack_json_data = parse_floss_json_bytes(stack_out, self.log, "stack stdout")
        decode_json_data = parse_floss_json_bytes(dec_out, self.log, "decode stdout")

        stack_strings_data = (
            stack_json_data.get("strings", {}) if isinstance(stack_json_data.get("strings", {}), dict) else {}
        )

        static_by_header = _extract_static_strings_by_header(stack_strings_data.get("static_strings", []))
        for header, static_strings in static_by_header.items():
            result_section = static_result(header, static_strings, max_length, st_max_size)
            if result_section:
                result.add_section(result_section)

        stack_strings = _extract_strings(stack_strings_data.get("stack_strings", []))
        if stack_strings:
            result_section = stack_result(stack_strings)
            if result_section:
                result.add_section(result_section)

        # Decode strings, reduce noise, then emit final decoded section.
        decode_strings_data = (
            decode_json_data.get("strings", {}) if isinstance(decode_json_data.get("strings", {}), dict) else {}
        )
        decoded_strings = _extract_strings(decode_strings_data.get("decoded_strings", []))
        decoded_strings = clean_decoded_strings(decoded_strings, stack_strings)
        if decoded_strings:
            decoding_scores = extract_decoding_scores(decode_json_data)
            decoded_body = format_decoded_body(decoded_strings, decoding_scores)
            result_section = decoded_result(decoded_strings, body_text=decoded_body)
            if result_section:
                if dec_err:
                    result_section.add_line("Flare Floss generated error messages while analyzing:")
                    result_section.add_line(safe_str(dec_err))
                result.add_section(result_section)

    def handle_process(self, process: Popen[bytes], timeout: float, command_name: str) -> tuple[bytes, bytes, bool]:
        """Handle a running subprocess.

        process: the running subprocess
        timeout: the length of time to wait for the subprocess
        command_name: the name of the command running in the subprocess

        Returns:
            A tuple of (stdout, stderr, timed_out).
        """
        timed_out = False
        try:
            output, error = process.communicate(timeout=max(timeout, 10))
            if process.returncode == -9:
                self.log.warning(f"Floss subprocess {command_name} killed before timeout")
                timed_out = True
            # There's a vivisect bug that can't be fixed until a new version is used in floss
            elif (
                process.returncode != 0
                and b"Vivisect failed to load the input file: float division by zero" not in error
            ):
                self.log.error(
                    f'"{command_name}" returned a non-zero exit status{process.returncode}\nstderr:\n{safe_str(error)}'
                )
        except TimeoutExpired:
            process.kill()
            output, error = process.communicate()
            timed_out = True

        return output, error, timed_out
