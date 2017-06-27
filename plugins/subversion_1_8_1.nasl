#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71566);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/10/06 23:50:20 $");

  script_cve_id("CVE-2013-2088", "CVE-2013-4131");
  script_bugtraq_id(60265, 61454);
  script_osvdb_id(93793, 93794, 95885);

  script_name(english:"Apache Subversion 1.6.x / 1.7.x / 1.8.x < 1.6.23 / 1.7.11 / 1.8.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Server is affected by the
following vulnerabilities :

  - An input validation error exists in two files in the
    'contrib/' directory that could allow arbitrary code
    execution. Note that this issue does not affect version
    1.8.0. (CVE-2013-2088)

  - An error exists related to the 'mod_dav_svn' Apache
    module that could allow denial of service attacks. Note
    that this issue does not affect the 1.6.x branch.
    (CVE-2013-4131)");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-2088-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2013-4131-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.6.23 / 1.7.11 / 1.8.1 or later, or
apply the vendor patches or workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
# 1.6.x < 1.6.23
# 1.7.x < 1.7.11
# 1.8.x < 1.8.1
if (
  (ver_compare(ver:version, fix:'1.6.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.6.23', strict:FALSE) == -1) ||
  (ver_compare(ver:version, fix:'1.7.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.11', strict:FALSE) == -1) ||
  (ver_compare(ver:version, fix:'1.8.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.8.1', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1.6.23 / 1.7.11 / 1.8.1' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
