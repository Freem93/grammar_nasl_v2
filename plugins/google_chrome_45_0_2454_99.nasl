#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86061);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id(
    "CVE-2015-5567",
    "CVE-2015-5568",
    "CVE-2015-5570",
    "CVE-2015-5571",
    "CVE-2015-5572",
    "CVE-2015-5573",
    "CVE-2015-5574",
    "CVE-2015-5575",
    "CVE-2015-5576",
    "CVE-2015-5577",
    "CVE-2015-5578",
    "CVE-2015-5579",
    "CVE-2015-5580",
    "CVE-2015-5581",
    "CVE-2015-5582",
    "CVE-2015-5584",
    "CVE-2015-5587",
    "CVE-2015-5588",
    "CVE-2015-6676",
    "CVE-2015-6677",
    "CVE-2015-6678",
    "CVE-2015-6679",
    "CVE-2015-6682"
  );
  script_osvdb_id(
    127803,
    127804,
    127805,
    127806,
    127807,
    127808,
    127809,
    127810,
    127811,
    127812,
    127813,
    127814,
    127815,
    127816,
    127817,
    127818,
    127819,
    127820,
    127821,
    127822,
    127823,
    127824,
    127825
  );

  script_name(english:"Google Chrome < 45.0.2454.99 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 45.0.2454.99. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified stack corruption issue exists that
    allows a remote attacker to execute arbitrary code.
    (CVE-2015-5567, CVE-2015-5579)

  - A vector length corruption issue exists that allows a
    remote attacker to have an unspecified impact.
    (CVE-2015-5568)

  - A use-after-free error exists in an unspecified
    component due to improperly sanitized user-supplied
    input. A remote attacker can exploit this, via a
    specially crafted file, to deference already freed
    memory and execute arbitrary code. (CVE-2015-5570,
    CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
    CVE-2015-6682)

  - An unspecified flaw exists due to a failure to reject
    content from vulnerable JSONP callback APIs. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-5571)

  - An unspecified flaw exists that allows a remote attacker
    to bypass security restrictions and gain access to
    sensitive information. (CVE-2015-5572)

  - An unspecified type confusion flaw exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2015-5573)

  - A flaw exists in an unspecified component due to
    improper validation of user-supplied input when handling
    a specially crafted file. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2015-5575,
    CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
    CVE-2015-5582, CVE-2015-5588, CVE-2015-6677)

  - A memory leak issue exists that allows a remote
    attacker to have an unspecified impact. (CVE-2015-5576)

  - A stack buffer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-5587)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-6676,
    CVE-2015-6678)

  - An unspecified flaw exists that allows a remote attacker
    to bypass same-origin policy restrictions and gain
    access to sensitive information. (CVE-2015-6679)");
  # http://googlechromereleases.blogspot.com/2015/09/stable-channel-update.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?96b510c5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 45.0.2454.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'45.0.2454.99', severity:SECURITY_HOLE);
