# Yara Service

This Assemblyline service runs the Yara application against all file types.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Service Configuration

Configurations of the service are contained within the
'SERVICE_DEFAULT_CONFIG' class variable. Each of these additional
configurations are explained below:


```
    SERVICE_DEFAULT_CONFIG = {
        **"USE_RIAK_FOR_RULES": True,                         # Store rules in AL datastore.
        **"RULE_PATH": 'rules.yar',                           # File path where cached rule file is stored/path of signature file when USE_RIAK_FOR_RULES is False.
        **"SIGNATURE_USER": 'user',                           # Datastore username to access signatures.
        **"SIGNATURE_PASS": 'changeme',                       # Datastore password to access signatures.
        "SIGNATURE_URL": 'https://localhost:443',             # AL server containing signatures. i.e. A staging instance of AL can be point to a production instance, so that signatures are stored only in one place.
        "SIGNATURE_QUERY": 'meta.al_status:DEPLOYED OR        # Signature filter when using AL datastore for ruleset. i.e. Add 'OR meta.al_status:STAGING' for your AL staging instance to test new signatures.
                            meta.al_status:NOISY',
        "VERIFY": False                                       # True if SSL connection to SIGNATURE_URL should be verified.
    }
** Setup at system installation and should only be changed with unique signature storage solution.
```


## Execution

Currently AL runs Yara 3.8.1, and therefore supports the following external modules:

* Dotnet
* ELF
* Hash
* Magic
* Math
* PE

## Rule Creation
 
 AL Yara rules follow the MALWARE standard. Detailed information on writing Yara rules, as well as the MALWARE standard,
 can be found at the following locations:
 
 Rule creation:
 
 * https://yara.readthedocs.io/en/v3.8.1
 
 * https://[AL instance]/static/pdf/yara.pdf
 
 MALWARE Standard:
 
 * https://[AL instance]/yara_standard.html
 
 AL Custom Conditions:

The following are the default externals provided in AL:

 * al_mime == the filename of the submitted file (fileinfo.mime)

 * al_tag == the AL file type category (fileinfo.tag)

 * al_submitter == the userid of the submitter of the AL file (submission.submitter)
 
 Additional conditions can be added in AL configuration under system.yara.externals. Please read reference manual
 for further information.


 **NOTE: AL custom conditions are meant to aid with large amounts of live data ingestion where the submission source, 
 filetype, etc. can be used to reduce false positives without disabling rules entirely.
 When creating Yara rules in AL with the above conditions, remember that there is no way to override
 these conditions**

## Importing Rules

 YARA rules can be adjusted/imported/reviewed in the AL GUI available at https://[AL instance]/signatures.html 
 
 For large ruleset imports, a Python importer script is located at assemblyline.al.run.yara_importer.py: 
 
    Usage: yara_importer.py [options] file1 file2 ... fileN

    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -f, --force           Force usage of default values without prompting
      -u, --utf8            Force utf8 encoding of everything
      -j JSON, --json=JSON  Default json values
      -o OUTFILE, --outfile=OUTFILE
                            Set output file
      -s, --save            Store directly in AL
      -V, --verbose         Verbose mode

 A safe way to run this script is to first save the ruleset to disk (using the '-o' option), rather than saving directly 
 to AL. You can then re-run the script on the new output file once you are satisfied with the results.
 