#!/usr/bin/env python

import json
import datetime
import dateutil.parser
import os
from cpe import CPE
import requests
import sys

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
def fetch_1(k):

    first_call="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=%s&startIndex=0&resultsPerPage=1" % k
    r=requests.get(first_call)

    if r.status_code != 200:
        print("Very bad")
        sys.exit(-1)

    code=json.loads(r.text)
    results=int(code["totalResults"])

    skip=0
    create=0

    base_url="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=ruby&startIndex="
    for loop in range(0, results+21, 20):
        url=base_url + str(loop)
        r=requests.get(url)
        if r.status_code != 200:
            print("An error occured calling %s\n" % url)
            sys.exit(-1)
        code=json.loads(r.text)


        for i in code["result"]["CVE_Items"]:
            filename = i["cve"]["CVE_data_meta"]["ID"].upper().replace("-", "_")

            out = "--- !ruby/object:Dawn::Kb::UnsafeDependencyCheck\napplies:\n- rails\n- sinatra\n- padrino\n"
            out += "title: %s" % i["cve"]["CVE_data_meta"]["ID"]
            out += "\n"
            if "baseMetricV3" in i["impact"]:
                out += "cvss: %s" % i["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
            elif "baseMetricV2" in i["impact"]:
                out += "cvss: %s" % i["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
            else:
                out += "cvss: no vector available"

            out += "\n"
            out += "cve: %s"% i["cve"]["CVE_data_meta"]["ID"]
            out += "\n"
            out += "owasp: A9\n"
            out += "release_date: %s\n" % datetime.datetime.strftime(dateutil.parser.parse(i["publishedDate"]).date(), "%d/%m/%Y")
            out += "\n"
            out += "kind: :unsafe_dependency_check\n"
            out += "message: |-\n"
            out += " %s" % i["cve"]["description"]["description_data"][0]["value"]
            out += "\n"
            out += "check_family: :bulletin\n"
            out += "vulnerable_version_array:\n"
            needs_review = True

            if len(i["configurations"]["nodes"]) > 0:
                if i["configurations"]["nodes"][0]["operator"] == "OR":
                    cpe_match_array = i["configurations"]["nodes"][0]["cpe_match"]
                    out += "- :name: '%s'" % CPE(cpe_match_array[0]["cpe23Uri"]).get_product()[0]
                    out += "\n"
                    out += "  :version:\n"
                    for cpe in cpe_match_array:
                        if cpe["vulnerable"]:
                            cpe_uri = CPE(cpe["cpe23Uri"])
                            if cpe_uri.get_version()[0] != "*":
                                out += "  - %s" % cpe_uri.get_version()[0]
                                out += "\n"
                                needs_review = False
            if needs_review:
                filename += "_must_review"
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

def fetch_2(k):

    first_call="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordsearch=%s" % k
    r=requests.get(first_call)

    if r.status_code != 200:
        print("Very bad")
        sys.exit(-1)

    code=json.loads(r.text)
    results=int(code["totalResults"])

    skip=0
    create=0

    for i in code["vulnerabilities"]:
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
                out += "  :version:\n"
                for cpe in cpe_match_array:
                    if cpe["vulnerable"]:
                        cpe_uri = CPE(cpe["criteria"])
                        if cpe_uri.get_version()[0] != "*":
                            out += "  - %s" % cpe_uri.get_version()[0]
                            out += "\n"
                            needs_review = False
        if needs_review:
            filename += "_must_review"
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


k=["ruby", "rubygems", "sinatra", "padrino", "rubyonrails"]

for i in k:
    print("fetching checks for keyword: %s" % i)
    fetch_2(i)

