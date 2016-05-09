# ota2tar

Parses an Apple iOS OTA file and converts it to tar.

Only the Format 3.0 described [here](https://www.theiphonewiki.com/wiki/OTA_Updates) is supported.

This code is based heavily on Jonathan Levin's example code from his [blog article on the OTA file format](http://newosxbook.com/articles/OTA.html).

## Dependencies:

  - libarchive (a "recent-ish version"?) - I recommend installing it via homebrew on OS X


## Building:

Run:

    cd src
    make ota2tar

On linux, you may want to tweak src/Makefile a bit depending on where and how you got libarchive.

## Usage:

    Usage: ./ota2tar [?hvkzEo:] /path/to/ota/payload
      Options:
        -?/-h        Show this help message
        -v           Verbose output
        -k           Keep intermediate payload.ota file
        -z           Compress the resulting tar-ball
        -E           Extract executables only
        -o path      Output to path

