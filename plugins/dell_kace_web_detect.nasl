#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53492);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/10 18:00:55 $");

  script_name(english:"Dell KACE K2000 Web Detection");
  script_summary(english:"Looks for Dell KACE K2000");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for an operating system deployment appliance was
detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for a Dell KACE K2000 appliance was detected on the
remote host.  The K2000 is used to deploy operating system
installations via the network."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.kace.com/products/systems-deployment-appliance/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k2000_systems_deployment_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

kace_ver = UNKNOWN_VER;
found = FALSE;

headers = parse_http_headers(status_line:banner, headers:banner);
if (!isnull(headers))
{
  if (!isnull(headers['x-kace-version']))
  {
    found = TRUE;
    kace_ver = headers['x-kace-version'];
    if (kace_ver == 0) kace_ver = UNKNOWN_VER;
  }
}
if (kace_ver == UNKNOWN_VER)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : "/about",
    exit_on_fail : TRUE
  );
  if ("K2000 Remote Site Appliance" >< res[2])
  {
    found = TRUE;
    match = eregmatch(
      pattern : "\>K2000 Remote Site Appliance ([0-9\.]+)\</span\>",
      string  : res[2]
    );
    if (!isnull(match))
    kace_ver = match[1];
  }
}

if (!found) audit(AUDIT_WRONG_WEB_SERVER, port, 'Dell KACE K2000');

install = add_install(
  appname:'dell_kace_k2000',
  dir:'',
  ver:kace_ver,
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Dell KACE K2000',
    installs:install,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
