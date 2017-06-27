#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61563);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2012-1525",
    "CVE-2012-2049",
    "CVE-2012-2050",
    "CVE-2012-2051",
    "CVE-2012-4147",
    "CVE-2012-4148",
    "CVE-2012-4149",
    "CVE-2012-4150",
    "CVE-2012-4151",
    "CVE-2012-4152",
    "CVE-2012-4153",
    "CVE-2012-4154",
    "CVE-2012-4155",
    "CVE-2012-4156",
    "CVE-2012-4157",
    "CVE-2012-4158",
    "CVE-2012-4159",
    "CVE-2012-4160",
    "CVE-2012-4161",
    "CVE-2012-4162"
  );
  script_bugtraq_id(
    55005,
    55006,
    55007,
    55008,
    55010,
    55011,
    55012,
    55013,
    55015,
    55016,
    55017,
    55018,
    55019,
    55020,
    55022,
    55023,
    55024,
    55026,
    55027
  );
  script_osvdb_id(
    84613,
    84614,
    84615,
    84616,
    84617,
    84618,
    84619,
    84620,
    84621,
    84622,
    84623,
    84624,
    84625,
    84626,
    84627,
    84628,
    84629,
    84630,
    84631,
    84632
  );
  script_name(english:"Adobe Reader < 10.1.4 / 9.5.2 Multiple Vulnerabilities (APSB12-16) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 10.1.4 or 9.5.2. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified stack-based buffer overflow condition
    exists that allows an attacker to execute arbitrary
    code. (CVE-2012-2049)

  - An unspecified buffer overflow condition exists that
    allows an attacker to execute arbitrary code.
    (CVE-2012-2050)

  - Multiple unspecified memory corruption issues exist that
    allow an attacker to execute arbitrary code or cause a
    denial of service. (CVE-2012-2051, CVE-2012-4147,
    CVE-2012-4148, CVE-2012-4149, CVE-2012-4150,
    CVE-2012-4151, CVE-2012-4152, CVE-2012-4153,
    CVE-2012-4154, CVE-2012-4155, CVE-2012-4156,
    CVE-2012-4157, CVE-2012-4158, CVE-2012-4159,
    CVE-2012-4160, CVE-2012-4161, CVE-2012-4162)

  - An unspecified heap-based buffer overflow condition
    exists that allows an attacker to execute arbitrary
    code. (CVE-2012-1525)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://telussecuritylabs.com/threats/show/TSL20120814-01");
  script_set_attribute(attribute:"see_also", value:"http://j00ru.vexillium.org/?p=1175");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 10.1.4 / 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 2)
)
  fix = "9.5.2";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 4)
)
  fix = "10.1.4";
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
