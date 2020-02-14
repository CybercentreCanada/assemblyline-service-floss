# FireEye Labs Obfuscated String Solver #

This service uses FLOSS to find obfuscated strings such as stacked strings

#### Service Details

NOTE: This service does not require you to buy any licence and is preinstalled and working after a default installation.

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size 
(to prevent service backlog and timeouts). The defaults are
intentionally set at low sizes. Filters can be easily changed in the service configuration,
based on the amount of traffic/hardware your AL instance is running.**

- MAX_SIZE: Maximum size of submitted file for this service.
- MAX_LENGTH: String length maximum. Used in basic ASCII and UNICODE modules.
- ST_MAX_SIZE: String list maximum size. List produced by basic ASCII and
UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns.

This service does the following:

1. String Extraction:
    * executable/windows files:
        - FireEye Flare-FLOSS static strings modules (unicode and ascii). Matches IOC's only (see patterns.py)
        - FireEye Flare-FLOSS decoded strings modules
        - FireEye Flare-FLOSS stacked strings modules

#### Result Output
1. Static Strings (ASCII, UNICODE, BASE64):
    * Strings matching IOC patterns of interest [Result Text and Tag]
2. ASCII Hex Strings:
    * Content extraction of ascii hex data successfully decoded (any data over 500 bytes)
    [Extracted File]
    * IOC pattern matching for any successfully decoded data [Result Text and Tag]
    [Result Text and Tag]
3. FF Decoded Strings:
    * All strings [Result Text and Tag]
    * Strings matching IOC patterns of interest [Tag]
4. FF Stacked Strings:
    * All strings, group by likeness (determined by fuzzywuzzy library) [Result Text]
    * Strings matching IOC patterns of interest [Tag]
