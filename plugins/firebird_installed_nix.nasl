#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99133);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/03/31 18:40:12 $");

  script_name(english:"Firebird SQL Server for Linux Installed (credentialed check)");
  script_summary(english:"Detects Firebird SQL Server for Linux.");

  script_set_attribute(attribute:"synopsis", value:
"An open source database server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Firebird SQL Server, an open source database server, is installed on
the remote Linux host.");
  script_set_attribute(attribute:"see_also", value:"https://www.firebirdsql.org/");;
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:firebirdsql:firebird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

appname = "Firebird SQL Server";
version = NULL;

# Get the RPM version
# FirebirdCS and FirebirdSS are for 2.x
# Firebird is for 3.x
matches = eregmatch(string:rpms, pattern:"(^|\n)(Firebird(CS|SS|)-([0-9.]+)-\d+)\|");
if (empty_or_null(matches)) audit(AUDIT_PACKAGE_NOT_INSTALLED, appname);
version = matches[4];
package = matches[2];

register_install(
  app_name:appname,
  path:"unknown",
  version:version,
  cpe:"cpe:/a:firebirdsql:firebird",
  extra:make_array("Installed package", package)
);
report_installs(app_name:appname);
