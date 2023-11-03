""" FLOSS service """

import re
import time
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Iterable, List, Optional, Tuple

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.result import BODY_FORMAT
from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection
from fuzzywuzzy.process import extract

FLOSS = '/opt/floss'
MAX_TAG_LEN = 75


def group_strings(strings: Iterable[str]) -> List[List[str]]:
    """ Groups strings by similarity """
    # prevent double iteration if strings is a generator
    strings = list(strings)

    groups = []
    choices = set(string for string in strings)
    picked = set()
    for string in strings:
        if string in picked:
            continue
        sim_strings = [ls[0] for ls in
                       extract(string, choices, limit=50) if ls[1] > 75]
        for s in sim_strings:
            choices.remove(s)
            picked.add(s)
        if sim_strings:
            groups.append(sim_strings)
    return groups


def ioc_tag(text: bytes, result: ResultSection, just_network: bool = False) -> bool:
    """ Tags iocs found in text to result

    text: text to search for iocs
    result: ResultSection to tag with iocs
    just_network: whether non-network iocs should be skipped

    returns: whether iocs are found
    """
    pattern = PatternMatch()
    ioc = pattern.ioc_match(text, bogon_ip=True, just_network=just_network)
    for kind, values in ioc.items():
        for val in values:
            result.add_tag(kind, val[:MAX_TAG_LEN])
    # Return whether any IOCs were found
    return bool(ioc)


def static_result(section: List[bytes], max_length: int, st_max_size: int) -> Optional[ResultSection]:
    """ Generates a ResultSection from floss static strings output section """
    header = section[0]
    lines = section[1:]

    result = ResultSection(header.decode(errors='ignore'), body_format=BODY_FORMAT.MEMORY_DUMP)
    for line in lines:
        if len(line) > max_length:
            continue
        if ioc_tag(line, result, just_network=len(lines) > st_max_size):
            result.add_line(line.decode(errors='ignore'))
    return result if result.body else None


def stack_result(section: List[bytes]) -> Optional[ResultSection]:
    """ Generates a ResultSection from floss stacked strings output section """
    result = ResultSection('FLARE FLOSS Stacked Strings', body_format=BODY_FORMAT.MEMORY_DUMP,
                           heuristic=Heuristic(3))
    assert result.heuristic
    strings = section[1:]

    if not strings:
        return None

    groups = group_strings(s.decode() for s in strings)
    for group in groups:
        res = ResultSection(f"Group: '{min(group, key=len)}' Strings: {len(group)}", body='\n'.join(group),
                            body_format=BODY_FORMAT.MEMORY_DUMP)
        for string in group:
            ioc_tag(string.encode(), res, just_network=len(group) > 1000)
        result.add_subsection(res)

    if any(res.tags for res in result.subsections):
        result.heuristic.add_signature_id('stacked_ioc')

    return result


def decoded_result(text: bytes) -> Optional[ResultSection]:
    """ Generates a ResultSection from floss decoded strings output section """
    lines = text.splitlines()
    lines[0] = b'Most likely decoding functions:'
    body = b'\n'.join(lines[:-1])

    strings = re.findall(rb'^\[[A-Z]+\]\s+0x[0-9A-F]+\s+(.+)', body, flags=re.M)
    if not strings:
        return None

    result = ResultSection('FLARE FLOSS Decoded Strings', body_format=BODY_FORMAT.MEMORY_DUMP, heuristic=Heuristic(1))
    assert result.heuristic
    ioc = False
    for string in strings:
        ioc = ioc_tag(string, result, just_network=len(strings) > 1000) or ioc
        result.add_tag('file.string.decoded', string[:75])
    if ioc:
        result.heuristic.add_signature_id('decoded_ioc')

    result.add_line(body.decode())
    return result


class Floss(ServiceBase):
    """ Service using the FireEye Labs Obfuscated String Solver

    see https://github.com/fireeye/flare-floss for documentation
    on the FLOSS tool
    """

    def execute(self, request: ServiceRequest) -> None:
        """ Main module see README for details. """
        start = time.time()

        result = Result()
        request.result = result
        file_path = request.file_path
        if request.deep_scan:
            # Maximum size of submitted file to run this service:
            max_size = 200000
            # String length maximum, used in basic ASCII and UNICODE modules:
            max_length = 1000000
            # String list maximum size
            # List produced by basic ASCII and UNICODE module results and will determine
            # if patterns.py will only evaluate network IOC patterns:
            st_max_size = 100000
            # Minimum string size for encoded/stacked string modules:
            enc_min_length = 7
            stack_min_length = 7
        else:
            max_size = self.config.get('max_size', 85000)
            max_length = self.config.get('max_length', 5000)
            st_max_size = self.config.get('st_max_size', 0)
            enc_min_length = self.config.get('enc_min_length', 7)
            stack_min_length = self.config.get('stack_min_length', 7)
        timeout = self.service_attributes.timeout-50

        if len(request.file_contents) > max_size:
            return

        stack_args = [FLOSS, f'-n {stack_min_length}', '--no-decoded-strings', file_path]
        decode_args = [FLOSS, f'-n {enc_min_length}', '-x', '--no-static-strings', '--no-stack-strings', file_path]

        with Popen(stack_args, stdout=PIPE, stderr=PIPE) as stack, \
                Popen(decode_args, stdout=PIPE, stderr=PIPE) as decode:
            stack_out, _, timed_out = self.handle_process(stack, timeout+start-time.time(), ' '.join(stack_args))
            if timed_out:
                result.add_section(ResultSection('FLARE FLOSS stacked strings timed out'))
                self.log.warning(f'floss stacked strings timed out for sample {request.sha256}')

            dec_out, dec_err, timed_out = self.handle_process(decode, timeout+start-time.time(), ' '.join(decode_args))
            if timed_out:
                result.add_section(ResultSection('FLARE FLOSS decoded strings timed out'))
                self.log.warning(f'floss decoded strings timed out for sample {request.sha256}')

        if stack_out:
            sections = [[y for y in x.splitlines() if y] for x in stack_out.split(b'\n\n')]
            for section in sections:
                if not section:  # skip empty
                    continue
                match = re.match(rb'FLOSS static\s+.*\s+strings', section[0])
                if match:
                    result_section = static_result(section, max_length, st_max_size)
                    if result_section:
                        result.add_section(result_section)
                    continue
                match = re.match(rb'.*\d+ stackstring.*', section[0])
                if match:
                    result_section = stack_result(section)
                    if result_section:
                        result.add_section(result_section)
                    continue

        # Process decoded strings results
        if dec_out:
            result_section = decoded_result(dec_out)
            if result_section:
                if dec_err:
                    result_section.add_line("Flare Floss generated error messages while analyzing:")
                    result_section.add_line(safe_str(dec_err))
                result.add_section(result_section)

    def handle_process(self, process: Popen[bytes], timeout: float, command_name: str) -> Tuple[bytes, bytes, bool]:
        """ Helper method for handling a subprocess

        process: the running subprocess
        timeout: the length of time to wait for the subprocess
        command_name: the name of the command running in the subprocess

        returns: the standard output and error of the process + whether if the processed timed out
        """
        timed_out = False
        try:
            output, error = process.communicate(timeout=max(timeout, 10))
            if process.returncode == -9:
                self.log.warning(f"Floss subprocess {command_name} killed before timeout")
                timed_out = True
            # There's a vivisect bug that can't be fixed until a new version is used in floss
            elif process.returncode != 0 and b'Vivisect failed to load the input file: float division by zero' not in error:
                self.log.error(f'"{command_name}" returned a non-zero exit status'
                               f'{process.returncode}\nstderr:\n{safe_str(error)}')
        except TimeoutExpired:
            process.kill()
            output, error = process.communicate()
            timed_out = True

        return output, error, timed_out
