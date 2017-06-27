#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42336);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/24 14:24:12 $");

  script_name(english:"AlienVault OSSIM Web Front End Detection");
  script_summary(english:"Checks for OSSIM.");

  script_set_attribute(attribute:"synopsis", value:
"The web front end for a security suite was detected on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The AlienVault Open Source Security Information Management (OSSIM)
web front end was detected on the remote host. OSSIM is a suite of
security tools used to monitor and maintain a network.");
  # http://web.archive.org/web/20110206014753/http://www.alienvault.com/products.php?section=OpenSourceSIM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69b0679d");
  script_set_attribute(attribute:"see_also", value:"https://www.alienvault.com/products/ossim");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alienvault:open_source_security_information_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

# Had some issues with request timeouts during testing so bumping this
# up.
port = get_http_port(default:443, php:TRUE);
app_name = "AlienVault OSSIM";

url = "/ossim/session/login.php";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  (
    "<title> AlienVault - Open Source SIM </title>" >< res[2] ||
    "<title> AlienVault - The Open Source SIM </title>" >< res[2] ||
    "<title> OSSIM Framework Login" >< res[2] ||
    "<title> AlienVault - Open Source SIEM </title>" >< res[2] ||
    "<title>AlienVault OSSIM" >< res[2] ||
    "<h1> OSSIM Login" >< res[2] ||
    'alt="OSSIM logo"' >< res[2]
  ) &&
  '/pixmaps/ossim.png' >< res[2]
) installs = add_install(appname:'ossim', dir:"/ossim", port:port, installs:installs);
else audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

if (report_verbosity > 0)
{
  report = get_install_report(port:port, installs:installs, item:'/', display_name:app_name);
  security_note(port:port, extra:report);
}
else security_note(port);
