# Introduction 

This tool examines Docker image tags in a Docker Trusted Registry (DTR) and initiates or starts a security scan on a tag if necessary. A scan is necessary depending on the values returned for `should_rescan` and `last_scan_status` from the DTR API `/api/v0/repositories/{namespace}/{reponame}/tags/{reference}` where `reference` is the tag name. `namespace` refers to a DTR Organization.

# Running the tool

`dtrscan --user [DTR user] --token [DTR Access token]`

`dtrscan -h | --help` displays the help text.

The `--user` and `--token` parameters are required.

The script expects to read a yaml file that contains an array of the DTR namespaces (or Organizations) to be scanned

```
Namespaces:
  - repo1
```

The script will not run without the namespaces file. A file named `namespaces.yaml` in the current directory is used by default. Only namespaces listed in the file will be checked by the script.

The tool logs to the console only.

# Building the tool

Only code in the Go standard library is used with the exception of the yaml parser (there is no yaml parser in the standard library).

`go get gopkg.in/yaml.v2`

# Method

The code examines a JSON object that contains detail for a namespace/name/tag combination. If a repository has no tags it will be silently ignored.

The per-tag JSON contains data about all the vulnerabilities for all image layers but the script checks only 2 objects, `manifest` and `vuln_summary` (the JSON shown is an edited example)

        "manifest": {
	        "os": "linux"
	        "architecture": "amd64"
        "vuln_summary:" {
            "namespace": "app",
            "reponame": "webapp",
            "tag": "20.04.23-156789",
            "critical": 0,
            "major": 0,
            "minor": 0,
            "last_scan_status": 0,
            "check_completed_at": "0001-01-01T00:00:00Z",
            "should_rescan": false,
            "has_foreign_layers": false
        }

The manifest object is necessary because the `os` and `architecture` of a tag are required to invoke a scan.

Scans are initiated by sending a POST request to `/api/v0/imagescan/scan/{namespace}/{reponame}/{tag}/{os}/{arch}`


A request is sent to scan a tag based on the following rules:
        
1. If `last_scan_status` is 5 do nothing. This means a scan is Pending.

2. If the number of days since the last scan is greater than the value provided for the parameter `--days` start a scan.

    For example, if the `check_completed_at` date for a tag shows it was last scanned 30 days ago `--days 15` will force the tag to be scanned again. Any tag in any repository in the namespace that was scanned more than 15 days ago will be scanned. The tag will be scanned regardles of the value of `should_rescan` or `last_scan_status`.

3. If `should_rescan` is `false` and `last_scan_status = 6` do nothing. The scan is up-to-date.

4. If `should_rescan` is `true` start a scan.
        
5. If `last_scan_status` is `0`, `should_rescan` always appears to be `false`. Scan the image. 

    This combination seems to mean the image has never been scanned (for example, just pushed to DTR as a new image) or something else (unknown) happened. For this combination `check_completed_at` date returned is always `0001-01-01T00:00:00Z`
        
`last_scan_status` of 1 has also been observed but in each case `should_rescan` was `true` so a value of 1 is not handled explicitly since the tag meets one of the rules above.

Note that because DTR can set the `check_completed_at` date to `0001-01-01T00:00:00Z` scans can be more than 700,000 days 'out of date' because the comparison used for `--days` determines the number of days between the current date and year `0001.` 
