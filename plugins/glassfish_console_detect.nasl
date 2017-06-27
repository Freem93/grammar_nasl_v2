#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55929);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:44:56 $");

  script_name(english:"Oracle GlassFish Console");
  script_summary(english:"Detects the presence of the Oracle GlassFish console.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to access the administration console of the remote
Oracle GlassFish application server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Oracle GlassFish application server,
and has the administration console listening on an external IP.");
  # http://www.oracle.com/us/products/middleware/cloud-app-foundation/glassfish-server/overview/index.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?85f4fd5a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");
  script_require_ports("Services/www", 4848);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

# Check if GlassFish was detected on this host.
get_kb_item_or_exit("www/glassfish");

# By default, GlassFish's administration console listens on port 4848.
port = get_http_port(default:4848);

# Look for snippets of the administration console.
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : "/login.jsf",
  exit_on_fail : TRUE
);

if (
  "<title>Login</title>" >!< res[2] ||
  res[2] !~ 'title="Log In to.*(GlassFish|Sun Java System Application Server)'
) exit(0, "Oracle GlassFish's administration console was not found on port " + port + ".");

set_kb_item(name:"www/glassfish/console", value:TRUE);
set_kb_item(name:"www/" + port + "/glassfish/console", value:TRUE);

report = '\nOracle GlassFish\'s administration console detected on port ' + port + '.\n';

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
exit(0);
