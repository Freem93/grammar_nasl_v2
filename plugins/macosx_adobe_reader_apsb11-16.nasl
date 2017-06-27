#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55421);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2011-0579",
    "CVE-2011-0618",
    "CVE-2011-0619",
    "CVE-2011-0620",
    "CVE-2011-0621",
    "CVE-2011-0622",
    "CVE-2011-0623",
    "CVE-2011-0624",
    "CVE-2011-0625",
    "CVE-2011-0626",
    "CVE-2011-0627",
    "CVE-2011-0628",
    "CVE-2011-2094",
    "CVE-2011-2095",
    "CVE-2011-2096",
    "CVE-2011-2097",
    "CVE-2011-2098",
    "CVE-2011-2099",
    "CVE-2011-2100",
    "CVE-2011-2101",
    "CVE-2011-2102",
    "CVE-2011-2103",
    "CVE-2011-2104",
    "CVE-2011-2105",
    "CVE-2011-2106",
    "CVE-2011-2107"
  );
  script_bugtraq_id(
    47806,
    47807,
    47808,
    47809,
    47810,
    47811,
    47812,
    47813,
    47814,
    47815,
    47847,
    47961,
    48107,
    48240,
    48242,
    48243,
    48244,
    48245,
    48246,
    48247,
    48248,
    48249,
    48251,
    48252,
    48253,
    48255
  );
  script_osvdb_id(
    72331,
    72332,
    72333,
    72334,
    72335,
    72336,
    72337,
    72341,
    72342,
    72343,
    72344,
    72723,
    73055,
    73056,
    73057,
    73058,
    73059,
    73061,
    73062,
    73063,
    73064,
    73065,
    73066,
    73067,
    73068,
    73097
  );
  script_xref(name:"CERT", value:"264729");
  script_xref(name:"ZDI", value:"ZDI-11-218");
  script_xref(name:"ZDI", value:"ZDI-11-219");

  script_name(english:"Adobe Reader < 10.1 / 9.4.5 / 8.3 Multiple Vulnerabilities (APSB11-12, APSB11-12, APSB11-16) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 10.1, 9.4.5, or 8.3. It is, therefore, affected by the
following vulnerabilities :

  - Multiple buffer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2011-2094,
    CVE-2011-2095, CVE-2011-2097)

  - A heap overflow condition exists that allows an attacker
    to execute arbitrary code. (CVE-2011-2096)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2011-2098,
    CVE-2011-2099, CVE-2011-2103, CVE-2011-2105,
    CVE-2011-2106)

  - Multiple memory corruption issues exist that allow an
    attacker to crash the application. (CVE-2011-2104,
    CVE-2011-2105)

  - A DLL loading vulnerability exists that allows an
    attacker to execute arbitrary code. (CVE-2011-2100)

  - A cross-document script execution vulnerability exists
    that allows an attacker to execute arbitrary code.
    (CVE-2011-2101)

  - A unspecified vulnerability exists that allows an
    attacker to bypass security restrictions. (CVE-2011-2102)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-218");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-219");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 8.3 / 9.4.5 / 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (!get_kb_item("Host/MacOSX/Version"))
  audit(AUDIT_OS_NOT, "Mac OS X");

app = "Adobe Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] < 3)
  fix = "8.3";
else if (
  (ver[0] == 9 && ver[1] < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 5)
)
  fix = "9.4.5";
else if (ver[0] == 10 && ver[1] < 1)
  fix = "10.1";
else
  fix = "";

if (fix)
{
  info =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:info, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
