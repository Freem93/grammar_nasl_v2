#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84801);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id(
    "CVE-2014-0566",
    "CVE-2014-8450",
    "CVE-2015-3095",
    "CVE-2015-4435",
    "CVE-2015-4438",
    "CVE-2015-4441",
    "CVE-2015-4443",
    "CVE-2015-4444",
    "CVE-2015-4445",
    "CVE-2015-4446",
    "CVE-2015-4447",
    "CVE-2015-4448",
    "CVE-2015-4449",
    "CVE-2015-4450",
    "CVE-2015-4451",
    "CVE-2015-4452",
    "CVE-2015-5085",
    "CVE-2015-5086",
    "CVE-2015-5087",
    "CVE-2015-5088",
    "CVE-2015-5089",
    "CVE-2015-5090",
    "CVE-2015-5091",
    "CVE-2015-5092",
    "CVE-2015-5093",
    "CVE-2015-5094",
    "CVE-2015-5095",
    "CVE-2015-5096",
    "CVE-2015-5097",
    "CVE-2015-5098",
    "CVE-2015-5099",
    "CVE-2015-5100",
    "CVE-2015-5101",
    "CVE-2015-5102",
    "CVE-2015-5103",
    "CVE-2015-5104",
    "CVE-2015-5105",
    "CVE-2015-5106",
    "CVE-2015-5107",
    "CVE-2015-5108",
    "CVE-2015-5109",
    "CVE-2015-5110",
    "CVE-2015-5111",
    "CVE-2015-5113",
    "CVE-2015-5114",
    "CVE-2015-5115"
  );
  script_bugtraq_id(
    69825,
    75402,
    75735,
    75737,
    75738,
    75739,
    75740,
    75741,
    75743,
    75746,
    75747,
    75748,
    75749
  );
  script_osvdb_id(
    124509,
    124510,
    124511,
    124512,
    124513,
    124514,
    124515,
    124516,
    124517,
    124518,
    124519,
    124520,
    124521,
    124522,
    124523,
    124524,
    124525,
    124526,
    124527,
    124528,
    124529,
    124530,
    124531,
    124532,
    124533,
    124534,
    124535,
    124536,
    124537,
    124538,
    124539,
    124540,
    124541,
    124542,
    124543,
    124544,
    124545,
    124546,
    124547,
    124548,
    124549,
    124550,
    124551,
    124552
  );

  script_name(english:"Adobe Reader < 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 Multiple Vulnerabilities (APSB15-15)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is a version
prior to 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082. It is, 
therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-5093)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-5096, CVE-2015-5098, CVE-2015-5105)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5087,
    CVE-2015-5094, CVE-2015-5100, CVE-2015-5102,
    CVE-2015-5103, CVE-2015-5104, CVE-2015-3095,
    CVE-2015-5115, CVE-2014-0566)

  - An unspecified information disclosure vulnerability
    exists. (CVE-2015-5107)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to disclose arbitrary information.
    (CVE-2015-4449, CVE-2015-4450, CVE-2015-5088,
    CVE-2015-5089, CVE-2015-5092, CVE-2014-8450)

  - A stack overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-5110)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-4448,
    CVE-2015-5095, CVE-2015-5099, CVE-2015-5101,
    CVE-2015-5111,  CVE-2015-5113, CVE-2015-5114)

  - Multiple validation bypass issues exist that allow an
    attacker to escalate privileges. (CVE-2015-4446,
    CVE-2015-5090, CVE-2015-5106)

  - A validation bypass issue exists that allows an attacker
    to cause a denial of service condition. (CVE-2015-5091)

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5097,
    CVE-2015-5108, CVE-2015-5109)

  - Multiple flaws exist that allow an attacker to bypass
    restrictions on the JavaScript API execution.
    (CVE-2015-4435, CVE-2015-4438, CVE-2015-4441,
    CVE-2015-4445, CVE-2015-4447, CVE-2015-4451,
    CVE-2015-4452, CVE-2015-5085, CVE-2015-5086)

  - Multiple NULL pointer dereference flaws exist that allow
    an attacker to cause a denial of service condition.
    (CVE-2015-4443, CVE-2015-4444)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 10.1.15 / 11.0.12 / 2015.006.30060 /
2015.008.20082 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];
verui   = install['display_version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 10.x < 10.1.15
# 11.x < 11.0.12
# DC Classic < 2015.006.30060
# DC Continuous < 2015.008.20082
if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 15) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 12) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] < 30060) ||
  (ver[0] == 15 && ver[1] == 7) ||
  (ver[0] == 15 && ver[1] == 8 && ver[2] < 20082)
)
{
  port = get_kb_item('SMB/transport');
  if(!port) port = 445;

  report = '\n  Path              : '+path+
           '\n  Installed version : '+verui+
           '\n  Fixed version     : 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082' +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
