#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72744);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2014-0032");
  script_bugtraq_id(65434);
  script_osvdb_id(102927);

  script_name(english:"Apache Subversion 1.3.x - 1.7.14 / 1.8.x < 1.8.8 'mod_dav_svn' DoS");
  script_summary(english:"Checks Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Server is affected by an error
related to 'mod_dav_svn', the 'SVNListParentPath' configuration
option, and handling 'OPTIONS' requests that could allow denial of
service attacks.");
  script_set_attribute(attribute:"see_also", value:"http://subversion.apache.org/security/CVE-2014-0032-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1557320");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.7.16 / 1.8.8 or later, or apply the
vendor-supplied patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
# 1.3.0 through 1.7.14
# 1.8.0 through 1.8.5
# Note : 1.7.15, 1.8.6, and 1.8.7 contain
#        fixes, but were not released
if (
  (ver_compare(ver:version, fix:'1.3.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.0', strict:FALSE) == -1) ||
  (ver_compare(ver:version, fix:'1.7.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.7.15', strict:FALSE) == -1) ||
  (ver_compare(ver:version, fix:'1.8.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.8.6', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Packaged with     : ' + provider +
             '\n  Installed version : ' + version +
             '\n  Fixed versions    : 1.7.16 / 1.8.8' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, provider + ' ' + appname, version, path);
