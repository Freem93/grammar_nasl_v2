#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64914);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/27 21:59:35 $");

  script_name(english:"Buffalo LinkStation Detection");
  script_summary(english:"Looks for a Buffalo LinkStation device");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a storage device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Buffalo LinkStation device, a NAS storage device
with an embedded web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.buffalotech.com/products/network-storage");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Buffalo LinkStation";

url = "/";
initialPage = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if ('content="0;url=/cgi-bin/top.cgi"' >!< initialPage) audit(AUDIT_NOT_DETECT, appname, port);

installs = make_array();
url = "/cgi-bin/top.cgi";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  "<title>LinkStation - LS-" >< res[2] &&
  "(C) BUFFALO INC. All Rights Reserved." >< res[2] &&
  "Please Provide your User Name and Password" >< res[2]
)
{
  ver = NULL;
  match = eregmatch(string:res[2], pattern:"<title>LinkStation\s*-\s*(.*)[\s]+\(.*\)</title>");
  if (!isnull(match)) ver = match[1];

  installs = add_install(
    installs : installs,
    port     : port,
    dir      : "/",
    ver      : ver,
    appname  : "buffalo_linkstation"
  );
}
else audit(AUDIT_NOT_DETECT, appname, port);

set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : appname,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
