#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63455);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2012-1530",
    "CVE-2013-0601",
    "CVE-2013-0602",
    "CVE-2013-0603",
    "CVE-2013-0604",
    "CVE-2013-0605",
    "CVE-2013-0606",
    "CVE-2013-0607",
    "CVE-2013-0608",
    "CVE-2013-0609",
    "CVE-2013-0610",
    "CVE-2013-0611",
    "CVE-2013-0612",
    "CVE-2013-0613",
    "CVE-2013-0614",
    "CVE-2013-0615",
    "CVE-2013-0616",
    "CVE-2013-0617",
    "CVE-2013-0618",
    "CVE-2013-0619",
    "CVE-2013-0620",
    "CVE-2013-0621",
    "CVE-2013-0622",
    "CVE-2013-0623",
    "CVE-2013-0624",
    "CVE-2013-0626",
    "CVE-2013-0627",
    "CVE-2013-1376"
  );
  script_bugtraq_id(
    57263,
    57264,
    57265,
    57268,
    57269,
    57270,
    57272,
    57273,
    57274,
    57275,
    57276,
    57277,
    57282,
    57283,
    57284,
    57285,
    57286,
    57287,
    57289,
    57290,
    57291,
    57292,
    57293,
    57294,
    57295,
    57296,
    57297,
    65275
  );
  script_osvdb_id(
    88970,
    88971,
    88972,
    88973,
    88974,
    88975,
    88976,
    88977,
    88978,
    88979,
    88980,
    88981,
    88982,
    88983,
    88984,
    88985,
    88986,
    88987,
    88988,
    88989,
    88990,
    88991,
    88992,
    88993,
    88994,
    88995,
    88996,
    102685
  );

  script_name(english:"Adobe Reader < 11.0.1 / 10.1.5 / 9.5.3 Multiple Vulnerabilities (APSB13-02) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 11.0.1, 10.1.5, or 9.5.3. It is, therefore, affected by the
following vulnerabilities :

  - Multiple memory corruption conditions exist that allow
    an attacker to execute arbitrary code or cause a denial
    of service. (CVE-2012-1530, CVE-2013-0601,
    CVE-2013-0605, CVE-2013-0616, CVE-2013-0619,
    CVE-2013-0620, CVE-2013-0623)

  - A use-after-free error exists that allows an attacker to
    execute arbitrary code. (CVE-2013-0602)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2013-0603, CVE-2013-0604)

  - Multiple stack overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2013-0610,
    CVE-2013-0626)

  - Multiple unspecified buffer overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-0606, CVE-2013-0612, CVE-2013-0615,
    CVE-2013-0617, CVE-2013-0621, CVE-2013-1376)

  - Multiple integer overflow conditions exist that allow
    an attacker to execute arbitrary code. (CVE-2013-0609,
    CVE-2013-0613)

  - A privilege escalation vulnerability exists that allows
    a local attacker to execute arbitrary code.
    (CVE-2013-0627)

  - Multiple logic errors exist that allow an attacker to
    execute arbitrary code. (CVE-2013-0607, CVE-2013-0608,
    CVE-2013-0611, CVE-2013-0614, CVE-2013-0618)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to bypass access restrictions.
    (CVE-2013-0622, CVE-2013-0624)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.1 / 10.1.5 / 9.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if (
  (ver[0] == 9 && ver[1] < 5) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 3)
)
  fix = "9.5.3";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 5)
)
  fix = "10.1.5";
else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 1)
  fix = "11.0.1";
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
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
