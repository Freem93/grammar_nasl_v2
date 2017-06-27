#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85568);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id(
    "CVE-2015-3107",
    "CVE-2015-5125",
    "CVE-2015-5127",
    "CVE-2015-5128",
    "CVE-2015-5129",
    "CVE-2015-5130",
    "CVE-2015-5131",
    "CVE-2015-5132",
    "CVE-2015-5133",
    "CVE-2015-5134",
    "CVE-2015-5539",
    "CVE-2015-5540",
    "CVE-2015-5541",
    "CVE-2015-5544",
    "CVE-2015-5545",
    "CVE-2015-5546",
    "CVE-2015-5547",
    "CVE-2015-5548",
    "CVE-2015-5549",
    "CVE-2015-5550",
    "CVE-2015-5551",
    "CVE-2015-5552",
    "CVE-2015-5553",
    "CVE-2015-5554",
    "CVE-2015-5555",
    "CVE-2015-5556",
    "CVE-2015-5557",
    "CVE-2015-5558",
    "CVE-2015-5559",
    "CVE-2015-5560",
    "CVE-2015-5561",
    "CVE-2015-5562",
    "CVE-2015-5563",
    "CVE-2015-5564",
    "CVE-2015-5565",
    "CVE-2015-5566"
  );
  script_bugtraq_id(
    75087,
    76282,
    76283,
    76287,
    76288,
    76289,
    76291
  );
  script_osvdb_id(
    125910,
    125911,
    125912,
    125913,
    125914,
    125915,
    125916,
    125917,
    125918,
    125919,
    125920,
    125921,
    125922,
    125923,
    125924,
    125925,
    125926,
    125927,
    125928,
    125929,
    125930,
    125931,
    125932,
    125933,
    125934,
    125935,
    125936,
    125937,
    125938,
    125939,
    125940,
    125941,
    126086,
    126087,
    126597
  );

  script_name(english:"Google Chrome < 44.0.2403.155 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version number of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
prior to 44.0.2403.155. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5128,
    CVE-2015-5554, CVE-2015-5555, CVE-2015-5558,
    CVE-2015-5562)

  - An unspecified vulnerability exists related to vector
    length corruptions. (CVE-2015-5125)

  - Multiple user-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5550,
    CVE-2015-5551, CVE-2015-3107, CVE-2015-5556,
    CVE-2015-5130, CVE-2015-5134, CVE-2015-5539,
    CVE-2015-5540, CVE-2015-5557, CVE-2015-5559,
    CVE-2015-5127, CVE-2015-5563, CVE-2015-5561,
    CVE-2015-5564, CVE-2015-5565, CVE-2015-5566)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-5129, CVE-2015-5541)

  - Multiple buffer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5131,
    CVE-2015-5132, CVE-2015-5133)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5544,
    CVE-2015-5545, CVE-2015-5546, CVE-2015-5547,
    CVE-2015-5548, CVE-2015-5549, CVE-2015-5552,
    CVE-2015-5553)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-5560)");
  # http://googlechromereleases.blogspot.com/2015/08/stable-channel-update_11.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?e46da2dd");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 44.0.2403.155 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'44.0.2403.155', severity:SECURITY_HOLE);
