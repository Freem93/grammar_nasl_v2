#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73190);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_name(english:"3Com Web Management Interface Default Credentials");
  script_summary(english:"Tries to log into the remote host");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server can be accessed with a default set of
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote 3Com Web Management Interface that uses a set of known,
default credentials. Knowing these, an attacker can gain control of
the device.");
  script_set_attribute(attribute:"solution", value:
"Log into the server and change the passwords for any affected
accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:3com_switch");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/3com");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:TRUE);

server_name = http_server_header(port:port);
if (isnull(server_name)) exit(0, "The web server listening on port " + port + " does not send a Server response header.");
if ("3Com" >!< server_name) exit(0, "The web server listening on port " + port + " is not a 3Com Web Management Interface.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);
if (
  ' 401 ' >!< res ||
  'WWW-Authenticate:Basic realm="device"' >!< res
) exit(0, "The web server listening on port "+port+" does not look like it's a 3Com Web Management Interface.");


logins = make_array();
passes = make_array();
i = 0;

logins[i] = "Admin";
passes[i] = "3Com";
i++;

logins[i] = "admin";
passes[i] = "";
i++;

logins[i] = "admin";
passes[i] = "admin";
i++;

logins[i] = "manager";
passes[i] = "manager";
i++;

logins[i] = "security";
passes[i] = "security";
i++;


n = i;

info = '';
successful_logins = 0;
url = '/';

for (i=0; i<n; i++)
{
  login = logins[i];
  pass  = passes[i];

  init_cookiejar();

  req = http_mk_get_req(
    port        : port,
    item        : url,
    add_headers : make_array(
      'Authorization', string('Basic ', base64(str:login+":"+pass))
    )
  );
  res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);
  if (
    ' 200 ' >< res[0] &&
    'content="0; url=/dev01/html/index.htnc"' >< res[2]
  )
  {
    info += '\n  Username : ' + login +
            '\n  Password : ' + pass +
            '\n';

    successful_logins++;

    if (!thorough_tests) break;
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';

    if (successful_logins == 1) s = '';
    else s = 's';

    trailer =
      'and the following set' + s + ' of credentials :' +
      '\n' +
      info;

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The 3Com Switch Web Management Interface listening on port "+port+" is not affected.");
