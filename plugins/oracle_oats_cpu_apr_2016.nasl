#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90859);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/25 14:52:53 $");

  script_cve_id("CVE-2015-7501");
  script_bugtraq_id(78215);
  script_osvdb_id(129952, 130424);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Oracle Application Testing Suite Java Object Deserialization RCE (April 2016 CPU)");
  script_summary(english:"Checks version of Oracle Application Testing suite");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the
remote host is affected by a remote code execution vulnerability due
to unsafe deserialize calls of unauthenticated Java objects to the
Apache Commons Collections (ACC) library. An unauthenticated, remote
attacker can exploit this, by sending a crafted SOAP request, to
execute arbitrary code on the target host.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

app_name = "Oracle Application Testing Suite";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^12\.5\.0\.2\.")
{
  fix_ver = "12.5.0.2.605";
  fix = "23012288";
}
else if (version =~ "^12\.4\.0\.2\.")
{
  fix_ver = "12.4.0.2.250";
  fix = "23012275";
}

if (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Oracle home    : ' + ohome +
      '\n  Install path   : ' + subdir +
      '\n  Version        : ' + version +
      '\n  Required patch : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
