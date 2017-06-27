#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66268);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_bugtraq_id(55191);
  script_osvdb_id(85015, 85016, 85017, 85018, 85019);
  script_xref(name:"EDB-ID", value:"20760");

  script_name(english:"op5 Monitor < 5.7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of op5 Monitor");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application hosted on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of op5 Monitor hosted on the remote web server is earlier
than 5.7.3.  It is, therefore, affected by the following
vulnerabilities:

  - The 'status/hostgroup_grid' script fails to properly
    sanitize user-supplied input to the 'items_per_page'
    parameter, which could allow for a SQL injection attack.

  - A flaw exists in the 'command/submit' script that fails
    to validate the 'host' parameter, which could lead to
    cross-site scripting (XSS).

  - A cross-site request forgery (CSRF) vulnerability exists
    because the application does not require multiple steps
    or explicit confirmation for sensitive transactions.");
  # http://www.op5.com/news/support-news/known-issues/security-vulnerabilities-op5-monitor/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?977be06b");
  script_set_attribute(attribute:"solution", value:"Upgrade op5 Monitor to version 5.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:monitor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("op5_monitor_detect.nasl");
  script_require_keys("www/op5_monitor");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of the op5 Portal install.
port = get_http_port(default:443);

install = get_install_from_kb(appname:"op5_monitor", port:port, exit_on_fail:TRUE);
dir = install["dir"];
version = install["ver"];

url = build_url(port:port, qs:dir + "/");

appname = "op5 Monitor";
fix = '5.7.3';

# If we couldn't detect the version, we can't determine if the remote
# instance is vulnerable.
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, appname, port);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 5 ||
  (ver[0] == 5 && ver[1] < 7) ||
  (ver[0] == 5 && ver[1] == 7 && ver[2] < 3)
)
{
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  set_kb_item(name:'www/' + port + '/XSRF', value:TRUE);
  set_kb_item(name:'www/' + port + '/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
  security_note(port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
