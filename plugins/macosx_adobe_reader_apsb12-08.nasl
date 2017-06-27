#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58684);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2012-0724",
    "CVE-2012-0725",
    "CVE-2012-0751",
    "CVE-2012-0752",
    "CVE-2012-0753",
    "CVE-2012-0754",
    "CVE-2012-0755",
    "CVE-2012-0756",
    "CVE-2012-0767",
    "CVE-2012-0768",
    "CVE-2012-0769",
    "CVE-2012-0772",
    "CVE-2012-0773",
    "CVE-2012-0774",
    "CVE-2012-0775",
    "CVE-2012-0776",
    "CVE-2012-0777"
  );
  script_bugtraq_id(
    52032,
    52033,
    52034,
    52035,
    52036,
    52037,
    52040,
    52297,
    52299,
    52748,
    52914,
    52916,
    52949,
    52950,
    52951,
    52952
  );
  script_osvdb_id(
    79296,
    79297,
    79298,
    79299,
    79300,
    79301,
    79302,
    79817,
    79818,
    80706,
    80707,
    81244,
    81245,
    81246,
    81247,
    81248,
    81249
  );

  script_name(english:"Adobe Reader < 10.1.3 / 9.5.1 Multiple Vulnerabilities (APSB12-03, APSB12-05, APSB12-07, APSB12-08) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 10.1.3 or 9.5.1. It is, therefore, affected by the following
vulnerabilities :

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code via a crafted True
    Type Font (TFF). (CVE-2012-0774)

  - A memory corruption issue exists in JavaScript handling
    that allows an attacker to execute arbitrary code.
    (CVE-2012-0775)

  - A security bypass vulnerability exists in the Adobe
    Reader installer that allows an attacker to execute
    arbitrary code. (CVE-2012-0776)

  - A memory corruption issue exists in the JavaScript API
    that allows an attacker to execute arbitrary code or
    cause a denial of service. (CVE-2012-0777)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 10.1.3 / 9.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 \'cprt\' Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-12-03");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-03.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-08.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

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
  (ver[0] == 9 && ver[1] == 5 && ver[2] == 0)
)
  fix = "9.5.1";
else if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 3)
)
  fix = "10.1.3";
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
