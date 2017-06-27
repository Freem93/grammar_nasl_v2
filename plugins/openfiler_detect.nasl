#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51459);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"Openfiler Management Interface Detection");
  script_summary(english:"Looks for Openfiler's management interface login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The management interface for a storage system was detected on the
remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts the management interface for Openfiler, a
network storage operating system."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openfiler.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 446);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:446, dont_break:TRUE, embedded:FALSE);


# Check if we need to set the encapsulation manually.
#
# While apache_SSL_complain.nasl will normally handle this, that
# only happens if 446 is in the specified port range.
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if (banner =~ "<!DOCTYPE HTML .*You're speaking plain HTTP to an SSL-enabled server")
{
  for (encaps=ENCAPS_SSLv2; encaps<=ENCAPS_TLSv1; encaps++)
  {
    soc = open_sock_tcp(port, transport:encaps);
    if (soc)
    {
      send(socket:soc, data: 'GET / HTTP/1.0\r\n\r\n');
      banner = recv(socket:soc, length:4096);
      close(soc);

      if (banner && egrep(pattern:"^HTTP\/.+", string:banner))
      {
        set_kb_item(name:"Transport/SSL", value:port);
        k = "Transports/TCP/"+port;
        replace_kb_item(name:k, value:encaps);
        set_kb_banner(port: port, type:"get_http", banner: banner);
        replace_kb_item(name:"www/banner/"+port, value:banner);
        break;
      }
    }
  }
}



# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  if (!egrep(pattern:'^Server: *Apache', string:banner))
    exit(0, "The web server on port "+port+" isn't Apache, which Openfiler uses.");
}


dir = '';
url = dir + '/';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  (
    '<title>Openfiler Storage Control Center' >< res[2] ||
    '>Openfiler</a>. All rights reserved.<' >< res[2]
  ) &&
  '<form action="/account/login.html"' >< res[2]
)
{
  version = NULL;

  # nb: the version in the generator meta tag isn't necessarily granular.
  pat = '>Distro Release:.+Openfiler (.+ [0-9]+\\.[^"\'<>]+)';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  installs = add_install(
    appname  : 'openfiler',
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );
}
else exit(0, "Openfiler's management interface was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Openfiler"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
