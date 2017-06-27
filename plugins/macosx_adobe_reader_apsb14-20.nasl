#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77714);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2014-0560",
    "CVE-2014-0561",
    "CVE-2014-0562",
    "CVE-2014-0563",
    "CVE-2014-0565",
    "CVE-2014-0566",
    "CVE-2014-0567"
  );
  script_bugtraq_id(
    69823,
    69821,
    69822,
    69826,
    69824,
    69825,
    69827
  );
  script_osvdb_id(
    111533,
    111536,
    111534,
    111535,
    111538,
    111539,
    111537
  );

  script_name(english:"Adobe Reader <= 10.1.10 / 11.0.07 Multiple Vulnerabilities (APSB14-20) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is version
10.x equal to or prior to 10.1.10, or 11.x equal to or prior to
11.0.07. It is, therefore, affected by multiple vulnerabilities :

  - A use-after-free error exists that allows arbitrary code
    execution. (CVE-2014-0560)

  - A heap-based buffer overflow exists that allows
    arbitrary code execution. (CVE-2014-0561, CVE-2014-0567)

  - An input-validation error exists that allows universal
    cross-site scripting (UXSS) attacks. (CVE-2014-0562)

  - A memory corruption error exists that allows denial of
    service attacks. (CVE-2014-0563)

  - Memory corruption errors exist that allow arbitrary code
    execution. (CVE-2014-0565, CVE-2014-0566)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb14-20.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 10.1.12 / 11.0.09 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Affected for Mac is :
# 10.x <= 10.1.10
# 11.x <= 11.0.7
if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] <= 10) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 7)
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 10.1.12 / 11.0.09' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
