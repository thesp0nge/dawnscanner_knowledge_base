#!/usr/bin/env python

import json
import datetime
import dateutil.parser
import os
from cpe import CPE
import requests
import sys

def fetch_2(k):
    # CVE-2017-1000047 is a rbenv vulnerability. we can ignore it
    # CVE-2008-2376 is a ruby vulnerability.
    # CVE-2008-1447 is a DNS issue, a false positive in search
    # CVE-2006-6979 is for the ruby handler for amarok
    BLACKLIST=["CVE-2017-1000047", "CVE-2008-2376", "CVE-2008-1447", "CVE-2006-6979"]

    first_call="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=%s" % k
    r=requests.get(first_call)

    if r.status_code != 200:
        print("[!] NVD API get failed. Giving up")
        sys.exit(-1)

    code=json.loads(r.text)
    results=int(code["totalResults"])

    skip=0
    create=0

    for i in code["vulnerabilities"]:
        if i["cve"]["id"] not in BLACKLIST:
            filename = i["cve"]["id"].upper().replace("-", "_")

            out = "--- !ruby/object:Dawn::Kb::UnsafeDependencyCheck\napplies:\n- rails\n- sinatra\n- padrino\n"
            out += "title: %s" % i["cve"]["id"]
            out += "\n"
            if "cvssMetricV3" in i["cve"]["metrics"]:
                out += "cvss: %s" % i["cve"]["metrics"]["cvssMetricV3"][0]["cvssData"]["vectorString"]
            elif "cvssMetricV2" in i["cve"]["metrics"]:
                out += "cvss: %s" % i["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["vectorString"]
            elif "cvssMetricV31" in i["cve"]["metrics"]:
                out += "cvss: %s" % i["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]

            else:
                out += "cvss: no vector available"

            out += "\n"
            out += "cve: %s"% i["cve"]["id"]
            out += "\n"
            out += "name: %s"% i["cve"]["id"]
            out += "\n"
            out += "owasp: A9\n"
            out += "release_date: %s\n" % datetime.datetime.strftime(dateutil.parser.parse(i["cve"]["published"]).date(), "%d/%m/%Y")
            out += "\n"
            out += "kind: :unsafe_dependency_check\n"
            out += "message: |-\n"
            out += " %s" % i["cve"]["descriptions"][0]["value"]
            out += "\n"
            out += "check_family: :bulletin\n"
            out += "vulnerable_version_array:\n"
            needs_review = True

            if "configurations" in i["cve"] and len(i["cve"]["configurations"][0]["nodes"]) > 0:
                if i["cve"]["configurations"][0]["nodes"][0]["operator"] == "OR":
                    cpe_match_array = i["cve"]["configurations"][0]["nodes"][0]["cpeMatch"]
                    out += "- :name: '%s'" % CPE(cpe_match_array[0]["criteria"]).get_product()[0]
                    out += "\n"
                    for cpe in cpe_match_array:
                        if cpe["vulnerable"]:
                            cpe_uri = CPE(cpe["criteria"])
                            if cpe_uri.get_version()[0] != "*":
                                out += "  :version:\n"
                                out += "  - %s" % cpe_uri.get_version()[0]
                                out += "\n"
                                needs_review = False
                            else:
                                if "versionEndExcluding" in cpe:
                                    out += "  :versionEndExcluding: " + cpe["versionEndExcluding"]+"\n"
                                    needs_review = False
                                elif "versionEndIncluding" in cpe:
                                    out += "  :versionEndIncluding: " + cpe["versionEndIncluding"]+"\n"
                                    needs_review = False
                                else:

                                    out += ":invalid:true\n\n"
                                    needs_review = True

            if needs_review:
                append_to_review_list("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=" + i["cve"]["id"])
            filename = filename + ".yml"

            full_filename = os.path.join("bulletin", filename)

            try:
                f = open(full_filename, "r")
                print("skipping %s that already exists" % full_filename)
                skip+=1
            except FileNotFoundError:
                print("creating %s" % full_filename)
                create+=1
                f = open(full_filename, "w")
                f.write(out)
            finally:
                f.close()

    print("%d checks created (%d skipped)" % (create, skip))

def append_to_review_list(cve:str):
    REVIEWED=["https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=CVE-2022-25765",
              "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=CVE-2019-1003086",
              "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=CVE-2016-10194",
              "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=CVE-2011-4319"]

    if cve not in REVIEWED:
        with open("to_review.txt", "a") as file_object:
            file_object.write(f"{cve}\n")

if __name__ == "__main__":

    version=datetime.date.today().strftime("%Y%m%d")
    print(f"[+] building knowledge base for dawnscanner version {version}")
    if os.path.exists("to_review.txt"):
        os.remove("to_review.txt")

    k=["ruby", "rubygems", "sinatra", "padrino", "rubyonrails"]

    # k=["CVE-2023-28846"]

    for i in k:
        print("fetching checks for keyword: %s" % i)
        fetch_2(i)

