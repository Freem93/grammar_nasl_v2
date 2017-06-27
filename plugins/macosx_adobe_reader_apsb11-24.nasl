#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56199);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
    "CVE-2011-1353",
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2424",
    "CVE-2011-2425",
    "CVE-2011-2426",
    "CVE-2011-2427",
    "CVE-2011-2428",
    "CVE-2011-2429",
    "CVE-2011-2430",
    "CVE-2011-2431",
    "CVE-2011-2432",
    "CVE-2011-2433",
    "CVE-2011-2434",
    "CVE-2011-2435",
    "CVE-2011-2436",
    "CVE-2011-2437",
    "CVE-2011-2438",
    "CVE-2011-2439",
    "CVE-2011-2440",
    "CVE-2011-2441",
    "CVE-2011-2442",
    "CVE-2011-2444"
  );
  script_bugtraq_id(
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49186,
    49572,
    49575,
    49576,
    49577,
    49578,
    49579,
    49580,
    49581,
    49582,
    49583,
    49584,
    49585,
    49586,
    49710,
    49714,
    49715,
    49716,
    49717,
    49718
  );
  script_osvdb_id(
    74432,
    74433,
    74434,
    74435,
    74436,
    74437,
    74438,
    74439,
    74440,
    74441,
    74442,
    74443,
    74444,
    75201,
    75429,
    75430,
    75431,
    75432,
    75433,
    75434,
    75435,
    75436,
    75437,
    75438,
    75439,
    75440,
    75441,
    75625,
    75626,
    75627,
    75628,
    75629,
    75630,
    97670,
    97671,
    97672
  );

  script_name(english:"Adobe Reader < 10.1.1 / 9.4.6 / 8.3.1 Multiple Vulnerabilities (APSB11-21, APSB11-24, APSB11-26) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 10.1.1, 9.4.6, or 8.3.1. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified error exists that allows an attacker to
    bypass security restrictions, resulting in code
    execution. (CVE-2011-2431)

  - Multiple buffer overflow conditions exists that allow an
    attacker to execute arbitrary code. (CVE-2011-2432,
    CVE-2011-2435)

  - Multiple heap overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2011-2433,
    CVE-2011-2434, CVE-2011-2436, CVE-2011-2437)

  - Multiple stack overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2011-2438)

  - An error exists related to memory leak issues that
    allows an attacker to execute arbitrary code.
    (CVE-2011-2439)

  - A use-after-free error exists that allows an attacker to
    execute arbitrary code. (CVE-2011-2440)

  - Multiple errors exist in the CoolType.dll library that
    can allow stack overflow conditions, resulting in code
    execution. (CVE-2011-2441)

  - A logic error exists that allows an attacker to execute
    arbitrary code. (CVE-2011-2442)

  - Multiple vulnerabilities exist, as noted in APSB11-21,
    that can allow an attacker to take control of the
    affected system or cause the application to crash.
    (CVE-2011-2130, CVE-2011-2134, CVE-2011-2135,
    CVE-2011-2136, CVE-2011-2137, CVE-2011-2138,
    CVE-2011-2139, CVE-2011-2140, CVE-2011-2414,
    CVE-2011-2415, CVE-2011-2416, CVE-2011-2417,
    CVE-2011-2425, CVE-2011-2424)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 10.1.1 / 9.4.6 / 8.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

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

if (
  (ver[0] == 8 && ver[1] < 3) ||
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 1)
)
  fix = "8.3.1";
else if (
  (ver[0] == 9 && ver[1] < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 6)
)
  fix = "9.4.6";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 1)
)
  fix = "10.1.1";
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
