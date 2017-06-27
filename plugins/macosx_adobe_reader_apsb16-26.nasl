#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92037);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/18 14:03:58 $");

  script_cve_id(
    "CVE-2016-4191",
    "CVE-2016-4192",
    "CVE-2016-4193",
    "CVE-2016-4194",
    "CVE-2016-4195",
    "CVE-2016-4196",
    "CVE-2016-4197",
    "CVE-2016-4198",
    "CVE-2016-4199",
    "CVE-2016-4200",
    "CVE-2016-4201",
    "CVE-2016-4202",
    "CVE-2016-4203",
    "CVE-2016-4204",
    "CVE-2016-4205",
    "CVE-2016-4206",
    "CVE-2016-4207",
    "CVE-2016-4208",
    "CVE-2016-4209",
    "CVE-2016-4210",
    "CVE-2016-4211",
    "CVE-2016-4212",
    "CVE-2016-4213",
    "CVE-2016-4214",
    "CVE-2016-4215",
    "CVE-2016-4250",
    "CVE-2016-4251",
    "CVE-2016-4252",
    "CVE-2016-4254",
    "CVE-2016-4255",
    "CVE-2016-4265",
    "CVE-2016-4266",
    "CVE-2016-4267",
    "CVE-2016-4268",
    "CVE-2016-4269",
    "CVE-2016-4270",
    "CVE-2016-6937",
    "CVE-2016-6938"
  );
  script_bugtraq_id(
    91710,
    91711,
    91712,
    91714,
    91716,
    92635,
    92636,
    92637,
    92640,
    92641,
    92643,
    93014,
    93016
  );
  script_osvdb_id(
    141302,
    141303,
    141304,
    141305,
    141306,
    141307,
    141308,
    141357,
    141358,
    141361,
    141362,
    141363,
    141364,
    141365,
    141366,
    141367,
    141368,
    141369,
    141370,
    141371,
    141372,
    141373,
    141374,
    141375,
    141376,
    141377,
    141378,
    141379,
    143420,
    143421,
    143422,
    143423,
    143424,
    143425,
    144408,
    144409
  );

  script_name(english:"Adobe Reader < 11.0.17 / 15.006.30198 / 15.017.20050 Multiple Vulnerabilities (APSB16-26) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 11.0.17, 15.006.30198, or 15.017.20050. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2016-4191, CVE-2016-4192,
    CVE-2016-4193, CVE-2016-4194, CVE-2016-4195,
    CVE-2016-4196, CVE-2016-4197, CVE-2016-4198,
    CVE-2016-4199, CVE-2016-4200, CVE-2016-4201,
    CVE-2016-4202, CVE-2016-4203, CVE-2016-4204,
    CVE-2016-4205, CVE-2016-4206, CVE-2016-4207,
    CVE-2016-4208, CVE-2016-4211, CVE-2016-4212,
    CVE-2016-4213, CVE-2016-4214, CVE-2016-4250,
    CVE-2016-4251, CVE-2016-4252, CVE-2016-4254,
    CVE-2016-4265, CVE-2016-4266, CVE-2016-4267,
    CVE-2016-4268, CVE-2016-4269, CVE-2016-4270,
    CVE-2016-6937)

  - An unspecified heap buffer overflow condition exists due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-4209)

  - An unspecified integer overflow condition exists that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-4210)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass the
    JavaScript API and execute arbitrary code.
    CVE-2016-4215)

  - An unspecified use-after-free error exists that allows
    an unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4255, CVE-2016-6938)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.17 / 15.006.30198 / 15.017.20050 
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
#
# 11.x < 11.0.17
# DC Classic < 15.006.30198
# DC Continuous < 15.017.20050
if (
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 16) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30174) ||
  (ver[0] == 15 && ver[1] >= 7 && ver[1] <= 16) ||
  (ver[0] == 15 && ver[1] == 17 && ver[2] <= 20045)
)
{
  report = '\n  Path              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 11.0.17 / 15.006.30198 / 15.017.20050' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
