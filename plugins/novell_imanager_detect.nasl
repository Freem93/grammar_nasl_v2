#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66034);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/19 20:24:46 $");

  script_name(english:"Novell iManager Detection");
  script_summary(english:"Detects Novell iManager Web Interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a network administration web application
listening."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to access the web interface of Novell iManager, a
network administration tool."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/consoles/imanager/overview.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:imanager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080, 8443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Novell iManager";

port = get_http_port(default:8443);

installs = NULL;

version = UNKNOWN_VER;

url = '/nps/servlet/portal';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>Novell iManager</title>' >!< res[2] ||
  'Username:' >!< res[2] || 
  'Password:' >!< res[2]
) audit(AUDIT_NOT_DETECT, appname, port);

# try multiple methods (from most to least likely to be accurate) to obtain
# version information

# this file is added when applying the latest patch (2.7.6 Patch 1)
url = '/nps/version.properties';
##Version and build number properties, do not modify!!!
##Tue Apr 09 16:29:27 IST 2013
#version=2.7.6
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ('version=' >< res[2])
{
  set_kb_item(name:'www/'+port+'/novell_imanager/version_properties', value:res[2]);
  item = eregmatch(pattern:'version=([0-9.]+)($|[^0-9.])', string:res[2]);
  if (!isnull(item)) version = item[1];
}

url = '/nps/build_oes.xml';
# <property name="Product.Name" value="nps"/>
# <property name="iManager.version" value="2.7"/>
# <property name="supportpack.version" value="6"/>
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (version == UNKNOWN_VER && 'iManager.version' >< res[2])
{
  item = eregmatch(pattern:'name="iManager.version"[ ]*value="([0-9.]+)"', string:res[2]);
  if (!isnull(item)) version = item[1];

  item = eregmatch(pattern:'name="supportpack.version"[ ]*value="([0-9]+)"', string:res[2]);
  if (!isnull(item)) version += '.' + item[1];
}

url = '/nps/packages/iman_mod_desc.xml';

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (version == UNKNOWN_VER && '<filename>iManager.npm</filename>' >< res[2])
{
  module = strstr(res[2], "<filename>iManager.npm</filename>");
  module = module - strstr(module, "</module>");

  tmp_version = "";
  if (module && "<version>" >< module && "</version>" >< module)
  {
    tmp_version = strstr(module, "<version>") - "<version>";
    tmp_version = tmp_version - strstr(tmp_version,'</version>');
  }

  if (tmp_version)
  {
    item = eregmatch(pattern:"([0-9.]+)", string:tmp_version);
    if (!isnull(item)) version = item[1];
  }
}

url = '/nps/version.jsp';

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (version == UNKNOWN_VER && res[2] =~ "^[0-9.]+[\r\n ]*$")
{
  item = eregmatch(pattern:"([0-9.]+)", string:res[2]);
  if (!isnull(item)) version = item[1];
}

installs = add_install(
  appname  : "novell_imanager",
  installs : installs,
  port     : port,
  dir      : '/nps',
  ver      : version
);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : "",
    display_name : appname
  );
  security_note(port:port, extra:report);
}
else security_note(port);
