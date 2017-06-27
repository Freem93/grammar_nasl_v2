#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38155);
  script_version("$Revision: 1.9 $");

  script_name(english:"Fortify 360 Web Interface Detection");
  script_summary(english:"Detects Fortify 360 Web Interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a source code auditing tool manager");

 script_set_attribute(attribute:"description", value:
"The remote web server is running the web interface for Fortify 360,
a web interface to analyze the results of source code audits.

As this interface is likely to contain sensitive information, make sure
only authorized personel can log into this site");
 script_set_attribute(attribute:"see_also", value:"http://www.fortify.com/");
 script_set_attribute( attribute:"solution", value:
"Make sure the proper access controls are put in place" );

  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/24");
 script_cvs_date("$Date: 2011/03/14 21:48:04 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8180);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8180);

# Loop through directories.
dirs = make_list("/f360", "/");
foreach dir (dirs)
{
  url = string(dir, "/login.jsp");
  w = http_send_recv3(method: "GET", item:url, port:port, exit_on_fail: 1);
  res = strcat(w[0], w[1], w[2]);
  if (
    '<title>Fortify 360 Server Login</title>' >< res &&
    'images/f360_logo.jpg' >< res )
  {
    set_kb_item(name:"www/" + port + "/fortify360", value:"fortify360 under " + dir);
    security_note(port:port, extra:'Fortify360 is reachable under ' + dir);
    exit(0);
  }
}
