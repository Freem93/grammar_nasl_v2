#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79836);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 13:53:27 $");

  script_cve_id(
    "CVE-2014-0580",
    "CVE-2014-0587",
    "CVE-2014-8443",
    "CVE-2014-9162",
    "CVE-2014-9163",
    "CVE-2014-9164"
  );
  script_bugtraq_id(
    71581,
    71582,
    71583,
    71584,
    71585,
    71586
  );
  script_osvdb_id(
    115557,
    115558,
    115559,
    115560,
    115561,
    115564
  );

  script_name(english:"Google Chrome < 39.0.2171.95 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is a
version prior to 39.0.2171.95. It is, therefore, affected by the
following vulnerabilities :

  - A security bypass vulnerability that allows an attacker
    to bypass the same-origin policy. (CVE-2014-0580)

  - Multiple memory corruption vulnerabilities that allow an
    attacker to execute arbitrary code. (CVE-2014-0587,
    CVE-2014-9164)

  - A use-after-free vulnerability that can result in
    arbitrary code execution. (CVE-2014-8443)

  - An unspecified information disclosure vulnerability.
    (CVE-2014-9162)

  - A stack-based buffer overflow vulnerability that can be
    exploited to execute arbitrary code or elevate
    privileges. (CVE-2014-9163)");
  # http://googlechromereleases.blogspot.com/2014/12/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b2222d2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 39.0.2171.95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'39.0.2171.95', severity:SECURITY_HOLE, xss:FALSE);
