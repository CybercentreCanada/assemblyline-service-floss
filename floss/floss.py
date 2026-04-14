"""FLOSS service"""

import json
import os
import tempfile
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
    """Groups strings by similarity"""
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
    """Tags iocs found in text to result

    text: text to search for iocs
    result: ResultSection to tag with iocs
    just_network: whether non-network iocs should be skipped

    returns: whether iocs are found
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
    """Generates a ResultSection from floss static strings JSON output"""
    result = ResultSection(header, body_format=BODY_FORMAT.MEMORY_DUMP)
    for string in strings:
        line = string.encode(errors="ignore")
        if len(line) > max_length:
            continue
        if ioc_tag(line, result, just_network=len(strings) > st_max_size):
            result.add_line(string)
    return result if result.body else None


def stack_result(strings: list[str]) -> ResultSection | None:
    """Generates a ResultSection from floss stack strings JSON output"""
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


def decoded_result(strings: list[str]) -> ResultSection | None:
    """Generates a ResultSection from floss decoded strings JSON output"""
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

    result.add_line("\n".join(strings))
    return result


def parse_floss_json_output(path: str, logger: Any) -> dict[str, object]:
    """Loads FLOSS JSON output from disk and removes the temporary file."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError) as err:
        # FLOSS may fail to write complete JSON when interrupted or failing analysis.
        # The service will continue and use available stderr/timeout details.
        logger.warning(f"Failed to parse FLOSS JSON output at {path}: {err}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {}


class Floss(ServiceBase):
    """Service using the FireEye Labs Obfuscated String Solver

    see https://github.com/fireeye/flare-floss for documentation
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

        with (
            tempfile.NamedTemporaryFile(suffix=".json", delete=False) as stack_json,
            tempfile.NamedTemporaryFile(suffix=".json", delete=False) as decode_json,
        ):
            stack_json_path = stack_json.name
            decode_json_path = decode_json.name

        stack_args = [FLOSS, "-n", str(stack_min_length), "-o", stack_json_path, "--no-decoded-strings", file_path]
        decode_args = [
            FLOSS,
            "-n",
            str(enc_min_length),
            "-o",
            decode_json_path,
            "-x",
            "--no-static-strings",
            "--no-stack-strings",
            file_path,
        ]

        with (
            Popen(stack_args, stdout=PIPE, stderr=PIPE) as stack,
            Popen(decode_args, stdout=PIPE, stderr=PIPE) as decode,
        ):
            _, _, timed_out = self.handle_process(stack, timeout + start - time.time(), " ".join(stack_args))
            if timed_out:
                result.add_section(ResultSection("FLARE FLOSS stacked strings timed out"))
                self.log.warning(f"floss stacked strings timed out for sample {request.sha256}")

            _, dec_err, timed_out = self.handle_process(decode, timeout + start - time.time(), " ".join(decode_args))
            if timed_out:
                result.add_section(ResultSection("FLARE FLOSS decoded strings timed out"))
                self.log.warning(f"floss decoded strings timed out for sample {request.sha256}")

        stack_json_data = parse_floss_json_output(stack_json_path, self.log)
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

        decode_json_data = parse_floss_json_output(decode_json_path, self.log)
        decode_strings_data = (
            decode_json_data.get("strings", {}) if isinstance(decode_json_data.get("strings", {}), dict) else {}
        )
        decoded_strings = _extract_strings(decode_strings_data.get("decoded_strings", []))
        if decoded_strings:
            result_section = decoded_result(decoded_strings)
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

        returns: the standard output and error of the process, plus whether it timed out
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
