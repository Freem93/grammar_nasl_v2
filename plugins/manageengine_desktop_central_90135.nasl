#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82472);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2015-2560");
  script_bugtraq_id(73380);
  script_osvdb_id(120026);

  script_name(english:"ManageEngine Desktop Central < 9 Build 90135 Unauthenticated Admin Password Reset");
  script_summary(english:"Checks the build number of Desktop Central.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that contains
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is prior to 9 build 90135. It is, therefore, affected by an
authentication bypass vulnerability due to a flaw in the
addOrModifyUser() method in the 'DCOperationsServlet' servlet. An
unauthenticated, remote attacker can exploit this issue to reset user
and admin passwords via a standard HTTP request to the
'DCOperationsServlet' servlet.");
  # https://www.manageengine.com/products/desktop-central/unauthorized-admin-credential-modification.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a4c0c60");
  # http://packetstormsecurity.com/files/131062/Manage-Engine-Desktop-Central-9-Unauthorized-Administrative-Password-Reset.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a354601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90135 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
build   = install["build"];
ismsp   = install["MSP"];
rep_version = version;
if(build !=  UNKNOWN_VER)
  rep_version += " Build "+build;
install_url =  build_url(port:port, qs:dir);

# MSP is not affected
if(ismsp)
  exit(0, "The Managed Service Providers edition of Desktop Central is not affected.");

if (version =~ "^9(\.|$)" && build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

# Only version 9 is affected, tested the PoC with last version of 8
build = int(build);
if (version =~ "^9(\.|$)" && build >= 90000 && build < 90135)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 9 Build 90135' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
