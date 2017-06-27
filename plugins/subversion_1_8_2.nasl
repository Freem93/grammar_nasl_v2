#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71567);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2013-4246", "CVE-2013-7393");
  script_bugtraq_id(62266, 68966);
  script_osvdb_id(96929, 109720);

  script_name(english:"Apache Subversion 1.8.x < 1.8.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Subversion Server installed on the remote host is prior
to version 1.8.2. It is, therefore, affected by multiple
vulnerabilities :

  - A repository corruption vulnerability related to
    'FileSystem atop the FileSystem' (FSFS) repositories
    and handling packed revision properties editing.
    (CVE-2013-4246)

  - A symlink privilege escalation vulnerability in
    'svnwcsub.py' and 'irkerbridge.py' exists when the
    --pidfile option is used. The option creates temporary
    files insecurely, and may allow a local attacker to use
    a symlink attack against a pid file to gain elevated
    privileges. (CVE-2013-7393)");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-4246-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2013-4262-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://svn.haxx.se/dev/archive-2013-08/0329.shtml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.8.3 or later, or apply the vendor patch
or workaround.

Note that version 1.8.2 was not publicly released, and thus version
1.8.3 is the recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Subversion Server';
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

path     = install['path'];
version  = install['version'];
provider = install['Packaged with'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# 1.8.x < 1.8.2 (not publicly released)
if (ver_compare(ver:version, fix:'1.8.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.8.2', strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.8.3' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
