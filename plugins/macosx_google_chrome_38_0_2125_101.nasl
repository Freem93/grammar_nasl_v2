#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78081);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2014-3188",
    "CVE-2014-3189",
    "CVE-2014-3190",
    "CVE-2014-3191",
    "CVE-2014-3192",
    "CVE-2014-3193",
    "CVE-2014-3194",
    "CVE-2014-3195",
    "CVE-2014-3196",
    "CVE-2014-3197",
    "CVE-2014-3198",
    "CVE-2014-3199",
    "CVE-2014-3200"
  );
  script_bugtraq_id(70262);
  script_osvdb_id(112747);

  script_name(english:"Google Chrome < 38.0.2125.101 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 37.0.2062.94. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in V8 and IPC that can lead to remote code
    execution. (CVE-2014-3188)

  - Out-of-bounds read errors exist in PDFium.
    (CVE-2014-3189, CVE-2014-3198)

  - Use-after-free errors exist in Events, Rendering, DOM,
    and Web Workers. (CVE-2014-3190, CVE-2014-3191,
    CVE-2014-3192, CVE-2014-3194)

  - A type confusion error exists in Session Management.
    (CVE-2014-3193)

  - Information leak vulnerabilities exist in the V8
    JavaScript engine and the XSS Auditor.
    (CVE-2014-3195, CVE-2014-3197)

  - A security bypass vulnerability exists in the Windows
    Sandbox. (CVE-2014-3196)

  - An error exists related to assertion of bindings in
    the V8 JavaScript engine. (CVE-2014-3199)

  - Multiple unspecified vulnerabilities exist.
    (CVE-2014-3200)");

  # http://googlechromereleases.blogspot.com/2014/10/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b44442f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 38.0.2125.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/07");

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

google_chrome_check_version(fix:'38.0.2125.101', severity:SECURITY_HOLE, xss:FALSE);
