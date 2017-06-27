#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(10302);
  script_version("$Revision: 1.39 $");
  script_osvdb_id(238);
  script_cvs_date("$Date: 2014/05/09 18:59:10 $");

  script_name(english:"Web Server robots.txt Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a 'robots.txt' file." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a file named 'robots.txt' that is intended to
prevent web 'robots' from visiting certain directories in a website for
maintenance or indexing purposes.  A malicious user may also be able to
use the contents of this file to learn of sensitive documents or
directories on the affected site and either retrieve them directly or
target them for other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.robotstxt.org/wc/exclusion.html" );
 script_set_attribute(attribute:"solution", value:
"Review the contents of the site's robots.txt file, use Robots META tags
instead of entries in the robots.txt file, and/or adjust the web
server's access controls to limit access to sensitive material." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for a web server's robots.txt");
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Try to retrieve the file.
w = http_send_recv3(method:"GET",item:"/robots.txt", port:port);
if (isnull(w)) exit(0);
res = w[2];

# nb: <http://www.robotstxt.org/wc/norobots-rfc.html> describes
#     how the file should look.
if (egrep(string:res, pattern:"^[ \t]*(A|Disa)llow:", icase:TRUE)) {
  if (report_verbosity > 0)
    security_note(port:port, extra: 'Contents of robots.txt :\n\n' + res);
  else
    security_note(port:port);
  exit(0);
}
