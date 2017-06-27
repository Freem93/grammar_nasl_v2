#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90195);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id(
    "CVE-2016-1646",
    "CVE-2016-1647",
    "CVE-2016-1648",
    "CVE-2016-1649",
    "CVE-2016-1650"
  );
  script_osvdb_id(
    136281,
    136282,
    136283,
    136284,
    136285,
    136296
  );

  script_name(english:"Google Chrome < 49.0.2623.108 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 49.0.2623.108. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in Google V8 that
    allows an attacker to crash the application, resulting
    in a denial of service. (CVE-2016-1646)

  - A use-after-free error exists in the Navigation
    component that allows an attacker to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-1647)

  - A use-after-free error exists in the Extensions
    component that allows an attacker to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-1648)

  - An overflow condition exists in libANGLE due to improper
    validation of user-supplied input. An attacker can
    exploit this to execute arbitrary code. (CVE-2016-1649)

  - An unspecified flaw exists in the pageCapture extension
    that allows an attacker to have an unspecified impact.
    (CVE-2016-1650)

  - A denial of service vulnerability exists in PDFium due
    to improper handling of file names. An attacker can
    exploit this to crash the application, resulting in a
    denial of service. (VulnDB 136296)");
  # http://googlechromereleases.blogspot.com/2016/03/stable-channel-update_24.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?7f954aee");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 49.0.2623.108 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'49.0.2623.108', severity:SECURITY_HOLE);
