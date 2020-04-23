# Floss Service

This service uses FireEye Labs Obfuscated String Solver (FLOSS) to find obfuscated strings such as stacked strings

https://github.com/fireeye/flare-floss/ - Licensed under Apache License 2.0 (https://github.com/fireeye/flare-floss/blob/master/LICENSE.txt)

#### Service Details

NOTE: This service does not require you to buy any licence and is pre-installed and working after a default installation.

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size (to prevent service backlog and timeouts). The defaults are intentionally set at low sizes. Filters can be easily changed in the service configuration, based on the amount of traffic/hardware your AL instance is running.**

- max_size: Maximum size of submitted file for this service.
- max_length: String length maximum. Used in basic ASCII and UNICODE modules.
- st_max_size: String list maximum size. List produced by basic ASCII and UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns.

This service does the following:

1. String Extraction:
    * executable/windows files:
        - Static strings modules (unicode and ascii). Matches IOC's only 
        - Decoded strings modules
        - Stacked strings modules

#### Result Output

1. Static Strings (ASCII, UNICODE, BASE64):
    * Strings matching IOC patterns of interest
2. ASCII Hex Strings:
    * Content extraction of ascii hex data successfully decoded (any data over 500 bytes)
    * IOC pattern matching for any successfully decoded data 
3. FF Decoded Strings:
    * All strings 
    * Strings matching IOC patterns of interest
4. FF Stacked Strings:
    * All strings, group by likeness (determined by fuzzywuzzy library)
    * Strings matching IOC patterns of interest
