#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100355);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/23 20:42:10 $");

  script_cve_id(
    "CVE-2017-2495",
    "CVE-2017-2496",
    "CVE-2017-2499",
    "CVE-2017-2500",
    "CVE-2017-2504",
    "CVE-2017-2505",
    "CVE-2017-2506",
    "CVE-2017-2508",
    "CVE-2017-2510",
    "CVE-2017-2511",
    "CVE-2017-2514",
    "CVE-2017-2515",
    "CVE-2017-2521",
    "CVE-2017-2525",
    "CVE-2017-2526",
    "CVE-2017-2528",
    "CVE-2017-2530",
    "CVE-2017-2531",
    "CVE-2017-2536",
    "CVE-2017-2538",
    "CVE-2017-2539",
    "CVE-2017-2544",
    "CVE-2017-2547",
    "CVE-2017-2549",
    "CVE-2017-6980",
    "CVE-2017-6984"
  );
  script_bugtraq_id(
    98454,
    98455,
    98456,
    98470,
    98473,
    98474
  );
  script_osvdb_id(
    153954,
    153962,
    157531,
    157532,
    157533,
    157534,
    157535,
    157536,
    157537,
    157538,
    157539,
    157540,
    157541,
    157544,
    157545,
    157546,
    157569,
    157582,
    157590,
    157600,
    157601,
    157602,
    157603,
    157604,
    157605,
    157667
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-05-15-7");

  script_name(english:"macOS : Apple Safari < 10.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X
host is prior to 10.1.1. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the history menu
    functionality. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2017-2495)

  - Multiple memory corruption issues exist in the WebKit
    component due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    these issues, by convincing a user to visit a specially
    crafted website, to execute arbitrary code.
    (CVE-2017-2496, CVE-2017-2505, CVE-2017-2506,
    CVE-2017-2514, CVE-2017-2515, CVE-2017-2521,
    CVE-2017-2525, CVE-2017-2526, CVE-2017-2530,
    CVE-2017-2531, CVE-2017-2538, CVE-2017-2539,
    CVE-2017-2544, CVE-2017-2547, CVE-2017-6980,
    CVE-2017-6984)

  - A memory corruption issue exists in the WebKit Web
    Inspector component that allows an unauthenticated,
    remote attacker to execute arbitrary code.
    (CVE-2017-2499)

  - An address bar spoofing vulnerability exists due to
    improper state management. An unauthenticated, remote
    attacker can exploit this to spoof the address in the
    address bar. (CVE-2017-2500, CVE-2017-2511)

  - Multiple universal cross-site scripting (XSS)
    vulnerabilities exist in WebKit due to improper handling
    of WebKit Editor commands, container nodes, pageshow
    events, frame loading, and cached frames. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted web page, to execute arbitrary script
    code in a user's browser session. (CVE-2017-2504,
    CVE-2017-2508, CVE-2017-2510, CVE-2017-2528,
    CVE-2017-2549)

  - Multiple unspecified flaws exist in WebKit that allow
    an unauthenticated, remote attacker to corrupt memory
    and execute arbitrary code by using specially crafted
    web content. (CVE-2017-2536)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207804");
  # https://lists.apple.com/archives/security-announce/2017/May/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a320df7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

if (!ereg(pattern:"Mac OS X 10\.(10|11|12)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X Yosemite 10.10 / Mac OS X El Capitan 10.11 / macOS Sierra 10.12");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path      = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version   = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "10.1.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, xss:true);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
