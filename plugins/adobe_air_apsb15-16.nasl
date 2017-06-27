#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84641);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_cve_id(
    "CVE-2014-0578",
    "CVE-2015-3097",
    "CVE-2015-3114",
    "CVE-2015-3115",
    "CVE-2015-3116",
    "CVE-2015-3117",
    "CVE-2015-3118",
    "CVE-2015-3119",
    "CVE-2015-3120",
    "CVE-2015-3121",
    "CVE-2015-3122",
    "CVE-2015-3123",
    "CVE-2015-3124",
    "CVE-2015-3125",
    "CVE-2015-3126",
    "CVE-2015-3127",
    "CVE-2015-3128",
    "CVE-2015-3129",
    "CVE-2015-3130",
    "CVE-2015-3131",
    "CVE-2015-3132",
    "CVE-2015-3133",
    "CVE-2015-3134",
    "CVE-2015-3135",
    "CVE-2015-3136",
    "CVE-2015-3137",
    "CVE-2015-4428",
    "CVE-2015-4429",
    "CVE-2015-4430",
    "CVE-2015-4431",
    "CVE-2015-4432",
    "CVE-2015-4433",
    "CVE-2015-5116",
    "CVE-2015-5117",
    "CVE-2015-5118",
    "CVE-2015-5119",
    "CVE-2015-5124"
  );
  script_bugtraq_id(
    75090,
    75568,
    75590,
    75591,
    75592,
    75593,
    75594,
    75595,
    75596
  );
  script_osvdb_id(
    124196,
    124244,
    124245,
    124246,
    124247,
    124248,
    124249,
    124250,
    124251,
    124252,
    124253,
    124254,
    124255,
    124256,
    124257,
    124258,
    124259,
    124260,
    124261,
    124262,
    124263,
    124264,
    124265,
    124266,
    124267,
    124268,
    124269,
    124270,
    124271,
    124273,
    124274,
    124275,
    124276,
    124277,
    124278,
    124975
  );

  script_name(english:"Adobe AIR <= 18.0.0.144 Multiple Vulnerabilities (APSB15-16)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Adobe AIR installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Windows host is equal or prior to 18.0.0.144. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists that
    allows an attacker to guess the address for the Flash
    heap. (CVE-2015-3097)

  - Multiple heap-based buffer overflow vulnerabilities
    exist that allow arbitrary code execution.
    (CVE-2015-3135, CVE-2015-4432, CVE-2015-5118)

  - Multiple memory corruption vulnerabilities exist that
    allow arbitrary code execution. (CVE-2015-3117,
    CVE-2015-3123, CVE-2015-3130, CVE-2015-3133,
    CVE-2015-3134, CVE-2015-4431)

  - Multiple NULL pointer dereference flaws exist.
    (CVE-2015-3126, CVE-2015-4429)

  - A security bypass vulnerability exists that results in
    an information disclosure. (CVE-2015-3114)

  - Multiple type confusion vulnerabilities exist that allow
    arbitrary code execution. (CVE-2015-3119, CVE-2015-3120,
    CVE-2015-3121, CVE-2015-3122, CVE-2015-4433)

  - Multiple use-after-free errors exist that allow
    arbitrary code execution. (CVE-2015-3118, CVE-2015-3124,
    CVE-2015-5117, CVE-2015-3127, CVE-2015-3128,
    CVE-2015-3129, CVE-2015-3131, CVE-2015-3132,
    CVE-2015-3136, CVE-2015-3137, CVE-2015-4428,
    CVE-2015-4430, CVE-2015-5119)

  - Multiple same-origin policy bypass vulnerabilities exist
    that allow information disclosure. (CVE-2014-0578,
    CVE-2015-3115, CVE-2015-3116, CVE-2015-3125,
    CVE-2015-5116)

  - A memory corruption issue exists due to improper
    validation of user-supplied input. An attacker can
    exploit this to execute arbitrary code. (CVE-2015-5124)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 18.0.0.180 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ByteArray Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '18.0.0.144';
fix = '18.0.0.180';
fix_ui = '18.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
