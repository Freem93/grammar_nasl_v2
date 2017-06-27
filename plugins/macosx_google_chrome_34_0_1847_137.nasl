#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74009);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2014-0510",
    "CVE-2014-0516",
    "CVE-2014-0517",
    "CVE-2014-0518",
    "CVE-2014-0519",
    "CVE-2014-0520",
    "CVE-2014-1740",
    "CVE-2014-1741",
    "CVE-2014-1742"
  );
  script_bugtraq_id(
    66241,
    67361,
    67364,
    67371,
    67372,
    67373,
    67374,
    67375,
    67376
  );
  script_osvdb_id(
    104585,
    105750,
    106886,
    106887,
    106888,
    106889,
    106890,
    106914,
    106915
  );

  script_name(english:"Google Chrome < 34.0.1847.137 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 34.0.1847.137. It is, therefore, affected by the
following vulnerabilities :

  - A use-after-free error exists in the included Flash
    version that could lead to arbitrary code execution.
    (CVE-2014-0510)

  - An unspecified error exists in the included Flash
    version that could allow a bypass of the same origin
    policy. (CVE-2014-0516)

  - Several security bypass errors exist in the included
    Flash version. (CVE-2014-0517, CVE-2014-0518,
    CVE-2014-0519, CVE-2014-0520)

  - Use-after-free errors exist related to 'WebSockets'
    and 'editing'. (CVE-2014-1740, CVE-2014-1742)

  - An integer overflow error exists related to DOM
    ranges. (CVE-2014-1741)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2014/05/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34109980");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-14.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 34.0.1847.137 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'34.0.1847.137', severity:SECURITY_HOLE);
