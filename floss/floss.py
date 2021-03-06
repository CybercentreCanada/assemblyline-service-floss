import re
import subprocess
import time

from subprocess import PIPE, TimeoutExpired

from fuzzywuzzy import process

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch

FLOSS = '/opt/floss'
MAX_TAG_LEN = 75

def group_strings(strings):
    # prevent double iteration if strings is a generator
    strings = list(strings)

    groups = []
    choices = set(string for string in strings)
    picked = set()
    for string in strings:
        if string in picked:
            continue
        sim_strings = [ls[0] for ls in
                       process.extract(string, choices, limit=50) if ls[1] > 75]
        for s in sim_strings:
            choices.remove(s)
            picked.add(s)
        if sim_strings:
            groups.append(sim_strings)
    return groups


def ioc_tag(string, result, just_network=False):
    pattern = PatternMatch()
    ioc = pattern.ioc_match(string, bogon_ip=True, just_network=just_network)
    for kind, values in ioc.items():
        for val in values:
            result.add_tag(kind, val[:MAX_TAG_LEN])
    # Return whether any IOCs were found
    return bool(ioc)


def static_result(section, max_length, st_max_size):
    header = section[0]
    strings = section[1:]

    result = ResultSection(header, body_format=BODY_FORMAT.MEMORY_DUMP)
    for string in strings:
        if len(string) > max_length:
            continue
        if ioc_tag(string, result, just_network=len(strings) > st_max_size):
            result.add_line(string)
    return result if result.body else None


def stack_result(section):
    result = ResultSection('FLARE FLOSS Sacked Strings', body_format=BODY_FORMAT.MEMORY_DUMP,
                           heuristic=Heuristic(3))
    strings = section[1:]

    if not strings:
        return None

    groups = group_strings(s.decode() for s in strings)
    for group in groups:
        res = ResultSection(f"Group: '{min(group, key=len)}' Strings: {len(group)}", body='\n'.join(group),
                            body_format=BODY_FORMAT.MEMORY_DUMP)
        for string in group:
            ioc_tag(string.encode(), res, just_network=len(group) > 1000)
        if res.tags:
            res.set_heuristic(4)
        result.add_subsection(res)

    return result


def decoded_result(text):
    lines = text.splitlines()
    lines[0] = b'Most likely decoding functions:'
    body = b'\n'.join(lines[:-1])
    strings = re.findall(rb'^\[[A-Z]+\]\s+0x[0-9A-F]+\s+(.+)', body, flags=re.M)
    if not strings:
        return None
    result = ResultSection('FLARE FLOSS Decoded Strings', body_format=BODY_FORMAT.MEMORY_DUMP)
    ioc = False
    for string in strings:
        ioc = ioc_tag(string, result, just_network=len(strings) > 1000) or ioc
        result.add_tag('file.string.decoded', string[:75])
    result.set_heuristic(2 if ioc else 1)

    result.add_line(body.decode())
    return result


class Floss(ServiceBase):
    def start(self):
        self.log.info('FLOSS service started')

    def stop(self):
        self.log.info('FLOSS service ended')

    def execute(self, request):
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

        stack = subprocess.Popen([FLOSS, f'-n {stack_min_length}', '--no-decoded-strings', file_path],
                                 stdout=PIPE, stderr=PIPE, text=True)
        decode_args = [FLOSS, f'-n {enc_min_length}', '-x', '--no-static-strings', '--no-stack-strings', file_path]
        decode = subprocess.Popen(decode_args, stdout=PIPE, stderr=PIPE, text=True)
        try:
            stack_out, stack_err = stack.communicate(timeout=max(timeout+start-time.time(), 10))
        except TimeoutExpired:
            stack.kill()
            stack.stdout.close()
            stack.stderr.close()
            stack = None
        try:
            dec_out, dec_err = decode.communicate(timeout=max(timeout+start-time.time(), 10))
        except TimeoutExpired:
            decode.kill()
            decode.stdout.close()
            decode.stderr.close()
            decode = None

        if stack is None or stack.returncode < 0:
            result.add_section(ResultSection('FLARE FLOSS stacked strings timed out'))
        elif stack.returncode != 0:
            raise RuntimeError(f'floss -n {stack_min_length} --no-decoded-strings '
                               f'returned a non-zero exit status {stack.returncode}\n'
                               f'stderr:\n{stack_err}')
        else:
            sections = [[y for y in x.splitlines() if y] for x in stack_out.encode().split(b'\n\n')]
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
        if decode is None or decode.returncode < 0:
            result.add_section(ResultSection('FLARE FLOSS decoded strings timed out'))
        elif decode.returncode != 0:
            raise RuntimeError(f'floss -n {enc_min_length} -x --no-static-strings --no-stack-strings '
                               f'returned a non-zero exit status {decode.returncode}\n'
                               f'stderr:\n{dec_err}')
        else:
            result_section = decoded_result(dec_out.encode())
            if result_section:
                if dec_err:
                    result_section.add_line("Flare Floss generated error messages while analyzing:")
                    result_section.add_line(dec_err)
                result.add_section(result_section)
