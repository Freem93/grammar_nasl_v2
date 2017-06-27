#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79802);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/08 16:16:56 $");

  script_name(english:"HP Network Node Manager i (NNMi) Linux Detection (credentialed check)");
  script_summary(english:"Detects installs of HP Network Node Manager i (NNMi).");

  script_set_attribute(attribute:"synopsis", value:"The remote host has network management software installed.");
  script_set_attribute(attribute:"description", value:
"The remote Linux host has HP Network Node Manager i (NNMi) installed.
NNMi is a component of HP Automated Network Management Suite.");
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1170657
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5003fcc1");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

appname = "HP Network Node Manager i";

# Get the RPM version
version = eregmatch(string:rpms, pattern:"(^|\n)HPOvNnmAS-([0-9.]+)-\d+\|");
if (empty_or_null(version)) audit(AUDIT_VER_FAIL, appname);
version = version[2];

register_install(
  app_name:appname,
  path:"/opt/OV", # Nix installer gives you no choice for this
  version:version,
  cpe:"cpe:/a:hp:network_node_manager_i"
);
report_installs(app_name:appname);
