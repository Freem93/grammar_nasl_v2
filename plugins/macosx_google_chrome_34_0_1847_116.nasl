#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73420);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/06/13 20:47:54 $");

  script_cve_id(
    "CVE-2014-0506",
    "CVE-2014-0507",
    "CVE-2014-0508",
    "CVE-2014-0509",
    "CVE-2014-1709",
    "CVE-2014-1716",
    "CVE-2014-1717",
    "CVE-2014-1718",
    "CVE-2014-1719",
    "CVE-2014-1720",
    "CVE-2014-1721",
    "CVE-2014-1722",
    "CVE-2014-1723",
    "CVE-2014-1724",
    "CVE-2014-1725",
    "CVE-2014-1726",
    "CVE-2014-1727",
    "CVE-2014-1728",
    "CVE-2014-1729"
  );
  script_bugtraq_id(66704);
  script_osvdb_id(
    104598,
    105535,
    105536,
    105537,
    105538,
    105539,
    105540,
    105541,
    105543,
    105546,
    105547,
    105548,
    105549,
    105550,
    105577,
    105578,
    105579,
    105580,
    105581,
    105582,
    105593,
    105594,
    105595,
    105596,
    105597,
    105598,
    105599,
    105600,
    105601,
    105602,
    139630
  );

  script_name(english:"Google Chrome < 34.0.1847.116 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 34.0.1847.116. It is, therefore, affected by the
following vulnerabilities :

  - A use-after-free error exists in the included Flash
    version that could lead to arbitrary code execution.
    (CVE-2014-0506)

  - A buffer overflow error exists in the included Flash
    version that could lead to arbitrary code execution.
    (CVE-2014-0507)

  - An unspecified error exists in the included Flash
    version that could allow a security bypass leading to
    information disclosure. (CVE-2014-0508)

  - An unspecified error exists in the included Flash
    version that could allow cross-site scripting attacks.
    (CVE-2014-0509)

  - An unspecified flaw exists related to IPC message
    injection that allows an unauthenticated, remote
    attacker to bypass sandbox restrictions. (CVE-2014-1709)

  - An input validation error exists that could allow
    universal cross-site scripting (UXSS) attacks.
    (CVE-2014-1716)

  - An unspecified out-of-bounds access error exists
    related to the V8 JavaScript engine. (CVE-2014-1717)

  - An integer overflow error exists related to the
    compositor. (CVE-2014-1718)

  - Use-after-free errors exist related to web workers,
    DOM processing, rendering, speech handling and forms
    handling. (CVE-2014-1719, CVE-2014-1720, CVE-2014-1722,
    CVE-2014-1724, CVE-2014-1727)

  - An unspecified memory corruption error exists related
    to the V8 JavaScript engine. (CVE-2014-1721)

  - An URL confusion error exists related to handling RTL
    characters. (CVE-2014-1723)

  - An out-of-bounds read error exists related to handling
    'window property' processing. (CVE-2014-1725)

  - An unspecified error exists that could allow local
    cross-origin bypasses. (CVE-2014-1726)

  - Various, unspecified memory handling errors exist.
    (CVE-2014-1728)

  - Various, unspecified errors exist related to the V8
    JavaScript engine. (CVE-2014-1729)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://googlechromereleases.blogspot.com/2014/04/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fd7963a");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 34.0.1847.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

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

google_chrome_check_version(fix:'34.0.1847.116', severity:SECURITY_HOLE, xss:TRUE);
