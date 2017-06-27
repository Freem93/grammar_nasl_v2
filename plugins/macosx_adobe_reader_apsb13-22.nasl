#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69847);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/03/17 15:23:32 $");

  script_cve_id(
    "CVE-2013-3351",
    "CVE-2013-3352",
    "CVE-2013-3353",
    "CVE-2013-3354",
    "CVE-2013-3355",
    "CVE-2013-3356",
    "CVE-2013-3357",
    "CVE-2013-3358"
  );
  script_bugtraq_id(
    62428,
    62429,
    62430,
    62431,
    62432,
    62433,
    62435,
    62436
  );
  script_osvdb_id(
    97054,
    97055,
    97056,
    97057,
    97058,
    97059,
    97060,
    97061
  );
  script_xref(name:"ZDI", value:"ZDI-13-230");

  script_name(english:"Adobe Reader < 11.0.4 / 10.1.8 Multiple Vulnerabilities (APSB13-22) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 11.0.4 or 10.1.8. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified stack overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-3351)

  - Multiple unspecified memory corruption issues exist that
    allow an attacker to execute arbitrary code.
    (CVE-2013-3352, CVE-2013-3354, CVE-2013-3355)

  - Multiple unspecified buffer overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-3353, CVE-2013-3356)

  - Multiple unspecified integer overflow conditions exist
    that allow an attacker to execute arbitrary code.
    (CVE-2013-3357, CVE-2013-3358)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-230/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.4 / 10.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

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
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 8)
)
  fix = "10.1.8";
else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 4)
  fix = "11.0.4";
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
