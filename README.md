# small-email-parser
To parse .eml files quickly and output them to txt, csv or json.

Installation:
Extract the zip file and open terminal and run the following command:
```
cargo run
```
Navigate to /target/debug open terminal and you can get parsing.
I personally place the .eml files in /target/debug to make it easier for myself.

Usage:
```
└─$ ./eml_parser -h           
Parses .eml files (single or batch) and extracts SPF, headers, and links

Usage: eml_parser [OPTIONS]

Options:
  -f, --file <file>      Path to a single .eml file
  -b, --batch <batch>    Path to a directory containing multiple .eml files
  -o, --output <output>  Output format: csv, json, or txt
  -h, --help             Print help
  -V, --version          Print version

```
