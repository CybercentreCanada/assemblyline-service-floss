"""FLOSS service."""

import json
import time
from collections.abc import Iterable
from subprocess import PIPE, Popen, TimeoutExpired

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


def decoded_result(strings: list[str], body_text: str) -> ResultSection | None:
    """Generates a ResultSection from FLOSS decoded strings JSON output.

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

        # Parse FLOSS v3.1.1 JSON output.
        # Schema: {"strings": {"static_strings": [{"string": ..., "encoding": ...}], ...}, "analysis": {...}}
        stack_data = self._parse_json(stack_out, "stack")
        decode_data = self._parse_json(dec_out, "decode")

        stack_strings: list[str] = []
        strings_obj = stack_data.get("strings", {})
        if isinstance(strings_obj, dict):
            # Static strings: group by encoding to create separate result sections
            static_by_encoding: dict[str, list[str]] = {}
            for entry in strings_obj.get("static_strings", []):
                header = f"FLOSS static {entry['encoding']} strings"
                static_by_encoding.setdefault(header, []).append(entry["string"])

            for header, statics in static_by_encoding.items():
                result_section = static_result(header, statics, max_length, st_max_size)
                if result_section:
                    result.add_section(result_section)

            # Stack strings
            stack_strings = [entry["string"] for entry in strings_obj.get("stack_strings", [])]
            if stack_strings:
                result_section = stack_result(stack_strings)
                if result_section:
                    result.add_section(result_section)

        # Decode strings, reduce noise, then emit final decoded section.
        decode_strings_obj = decode_data.get("strings", {})
        if isinstance(decode_strings_obj, dict):
            decoded_strings = list(
                dict.fromkeys(entry["string"] for entry in decode_strings_obj.get("decoded_strings", []))
            )
            decoded_strings = clean_decoded_strings(decoded_strings, stack_strings)
            if decoded_strings:
                # Extract decoding function scores
                decoded_scores: dict[int, float] = {}
                try:
                    for key, val in decode_data["analysis"]["functions"]["decoding_function_scores"].items():
                        decoded_scores[int(key)] = float(val["score"])
                except (KeyError, TypeError, ValueError):
                    pass

                decoded_body = format_decoded_body(decoded_strings, decoded_scores)
                result_section = decoded_result(decoded_strings, body_text=decoded_body)
                if result_section:
                    if dec_err:
                        result_section.add_line("Flare Floss generated error messages while analyzing:")
                        result_section.add_line(safe_str(dec_err))
                    result.add_section(result_section)

    def _parse_json(self, output: bytes, source: str) -> dict:
        """Parse FLOSS JSON output bytes.

        Args:
            output: The raw bytes output from a FLOSS subprocess.
            source: A string indicating the source of the output (e.g., "stack" or "decode") for logging purposes.

        Returns:
            A dictionary parsed from the JSON output, or an empty dictionary if parsing fails.
        """
        if not output:
            return {}
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            self.log.warning(f"Failed to parse FLOSS JSON from {source}: {err}")
        return {}

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
                    f'"{command_name}" returned a non-zero exit status {process.returncode}\nstderr:\n{safe_str(error)}'
                )
        except TimeoutExpired:
            process.kill()
            output, error = process.communicate()
            timed_out = True

        return output, error, timed_out
