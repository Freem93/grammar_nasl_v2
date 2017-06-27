#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35820);
  script_version("$Revision: 1.8 $");

  script_name(english:"Thecus NAS Device Detection");
  script_summary(english:"Looks at initial web page");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote host is a network-attached storage device."  );
  script_set_attribute( attribute:"description",   value:
"According to its web server, the remote host is a Thecus NAS (Network-
Attached Storage) device, which provides file-based data storage to
hosts across a network."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.thecus.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/10");
 script_cvs_date("$Date: 2011/03/15 18:34:12 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Make sure the banner looks like a Thecus NAS device.
banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Server: mini_httpd/" >< banner)
{
  # Check the initial page for evidence of Thecus.
  res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

  if (
    '<TITLE>Thecus NAS</TITLE>' >< res &&
    'NORESIZE SRC="/sys/cgi-bin/nas.cgi?choice=login?choice=login">' >< res
  ) security_note(0);
}
else if ("Server: Apache" >< banner)
{
  # Check the initial page for evidence of a Thecus N5200.
  res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

  if (
    '<title>Thecus N5200' >< res &&
    'form method="POST" action="/usr/usrgetform.html?name=index"' >< res
  ) security_note(port:port, extra:'\nThe remote host seems to be a Thecus N5200.');
}
