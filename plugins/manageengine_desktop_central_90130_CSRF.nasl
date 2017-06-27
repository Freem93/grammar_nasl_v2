#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82082);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2014-9331");
  script_bugtraq_id(72464);
  script_osvdb_id(117896);
  script_xref(name:"EDB-ID", value:"35980");

  script_name(english:"ManageEngine Desktop Central < 9 build 90103 XSRF");
  script_summary(english:"Checks the build number of Desktop Central.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that contains
a cross-site request forgery (XSRF) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central installed on the remote
host is prior to 9 Build 90103. It is, therefore, affected by an XSRF
vulnerability due to the failure of 'roleMgmt.do' to validate the
source of requests. A remote attacker, by enticing an administrative
user to follow a link to a malicious web server, can employ a crafted
HTML document to add a new administrative account to the system with a
password of the attacker's choosing.");
  # https://www.manageengine.com/products/desktop-central/cve20149331-cross-site-request-forgery.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e910282c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Feb/14");

  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90103 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

if(ismsp)
  exit(0, "The Managed Service Providers edition of Desktop Central is not known to be affected.");

if (version =~ "^9(\.|$)" && build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

if (int(build) < 90103)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 9 Build 90103' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
