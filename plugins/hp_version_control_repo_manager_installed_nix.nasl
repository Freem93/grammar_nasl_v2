#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85804);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/09/04 18:16:06 $");

  script_name(english:"HP Version Control Repository Manager Linux Detection (credentialed check)");
  script_summary(english:"Detects HP Version Control Repository Manager for Linux.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has version control repository management software
installed.");
  script_set_attribute(attribute:"description", value:
"HP Version Control Repository Manager, a software version management
application, is installed on the remote Linux host.");
  # http://www.hp.com/wwsolutions/misc/hpsim-helpfiles/mxhelp/mxportal/en/useTools_vc_about_vcrm.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6dab298");;
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_repository_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

rpms = get_kb_list("Host/*/rpm-list");
if(empty_or_null(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);
distro = keys(rpms);
distro = distro[0];
rpms   = rpms[distro];

appname = "HP Version Control Repository Manager for Linux";

# Get the RPM version
version = eregmatch(string:rpms, pattern:"(^|\n)cpqsrhmo-([0-9.]+)-\d+\|");
if (empty_or_null(version)) audit(AUDIT_VER_FAIL, appname);
version = version[2];

register_install(
  app_name:appname,
  path:"/opt/hp/vcrepository", # Nix installer gives you no choice for this
  version:version,
  cpe:"cpe:/a:hp:version_control_repository_manager"
);
report_installs(app_name:appname);
