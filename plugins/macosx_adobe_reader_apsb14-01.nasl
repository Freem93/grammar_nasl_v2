#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71949);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:08 $");

  script_cve_id(
    "CVE-2014-0493",
    "CVE-2014-0495",
    "CVE-2014-0496"
  );
  script_bugtraq_id(
    64802,
    64803,
    64804
  );
  script_osvdb_id(
    101979,
    101980,
    101981
  );

  script_name(english:"Adobe Reader < 10.1.9 / 11.0.6 Multiple Vulnerabilities (APSB14-01) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 10.1.9 or 11.0.6. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2014-0493,
    CVE-2014-0495)

  - A use-after-free error exists that allows an attacker to
    execute arbitrary code. (CVE-2014-0496)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb14-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 10.1.9 / 11.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

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
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 9)
)
  fix = "10.1.9";
else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 6)
  fix = "11.0.6";
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
