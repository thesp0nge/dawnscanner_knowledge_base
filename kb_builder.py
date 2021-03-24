#!/usr/bin/env python

import json
from cpe import CPE

f =open('foo.json', 'r')
a=f.read()
f.close
l=json.loads(a)

# ROOT
#
# resultsPerPage
# startIndex
# totalResults
# result
    # CVE_data_type
    # CVE_data_format
    # CVE_data_version
    # CVE_data_timestamp
    # CVE_Items

for i in l["result"]["CVE_Items"]:
    print(i["cve"]["CVE_data_meta"]["ID"])
    print(i["cve"]["description"]["description_data"][0]["value"])
    if i["configurations"]["nodes"][0]["operator"] == "OR":
        cpe_match_array = i["configurations"]["nodes"][0]["cpe_match"]
        for cpe in cpe_match_array:
            if cpe["vulnerable"]:
                print(cpe)

    # Test in AND configuration deserves more deep investigation
    # if i["configurations"]["nodes"][0]["operator"] == "AND":
    #     for j in i["configurations"]["nodes"][0]["children"]:
    #         print(j)
