#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62735);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/29 19:22:58 $");

  script_name(english:"WANem Detection");
  script_summary(english:"Detects installs of WANem");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an appliance that simulates a WAN network
connection."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is a WANem appliance.  WANem is a WAN emulator that
acts as an application gateway.  This gateway can be used by developers
to simulate various network conditions when testing / developing their
applications."
  );
  script_set_attribute(attribute:"see_also", value:"http://wanem.sourceforge.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tata:wanem");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = 'WANem';

installs  = NULL;

# this is a network appliance, the directory shouldn't change
dir = '/WANem';

# Try to access page.
res = http_send_recv3(
  method       : "GET",
  item         : dir + "/about.html",
  port         : port,
  exit_on_fail : TRUE
);

if ('<title>WANEM - The Wide Area Network Emulator</title>' >< res[2])
{ 
  version = UNKNOWN_VER;
 
  item = eregmatch(pattern: '<b>WANem v([0-9.]+)<', string:res[2]); 
  if (!isnull(item)) version = item[1];

  installs = add_install(
    appname  : "wanem",
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );
}

if (isnull(installs)) audit(AUDIT_NOT_LISTEN, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'wanem',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
