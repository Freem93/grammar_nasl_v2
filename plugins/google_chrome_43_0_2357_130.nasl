#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84342);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id(
    "CVE-2015-1266",
    "CVE-2015-1267",
    "CVE-2015-1268",
    "CVE-2015-1269"
  );
  script_osvdb_id(
    123530,
    123531,
    123532,
    123533
  );

  script_name(english:"Google Chrome < 43.0.2357.130 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 43.0.2357.130. It is, therefore, affected by multiple
vulnerabilities :

  - A scheme validation error exists in WebUI. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-1266)

  - A cross-origin bypass vulnerability exists in Blink due
    to an unspecified flaw that is triggered when handling
    the creation context passed through public APIs. A
    remote attacker can exploit this to bypass the
    cross-origin policy. (CVE-2015-1267)

  - A cross-origin bypass vulnerability exists in Blink due
    to an unspecified flaw in its V8 bindings. A remote
    attacker can exploit this to bypass the cross-origin
    policy. (CVE-2015-1268)

  - A normalization bypass vulnerability exists in the
    HSTS/HPKP preload list. A remote attacker can exploit
    this to bypass HSTS/HPKP preloads and have a connection
    use HTTP instead of the expected HTTPS. (CVE-2015-1269)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2015/06/chrome-stable-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b830981");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 43.0.2357.130 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'43.0.2357.130', severity:SECURITY_WARNING);
