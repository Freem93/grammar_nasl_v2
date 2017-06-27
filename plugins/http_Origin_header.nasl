#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(50343);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");

 script_name(english: "HTTP Origin Response Header Usage");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server takes some steps to mitigate a class of web
application vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote web server sets an Origin response header in some
responses. 

Origin has been proposed as a way to mitigate cross-site request
forgery and JSON data theft." );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-abarth-origin-05");
 script_set_attribute(attribute:"see_also", value:"http://dev.w3.org/2006/waf/access-control/#origin-request-header");
 script_set_attribute(attribute:"see_also", value:"https://wiki.mozilla.org/Security/Origin");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Reports pages that use Origin header");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded:TRUE);
l = get_kb_list("www/"+port+"/header/origin");
if (isnull(l))
 exit(0, "No Origin response headers were seen from the web server on port "+port+".");

l = make_list(l);
if (max_index(l) == 0)
 exit(0, "No Origin response headers were seen from the web server on port "+port+".");

if (report_verbosity < 1)
  security_note(port: port);
else
{
  r = '\nThe following pages use an Origin response header :\n\n';
  foreach u (l) r = strcat(r, '  - ', u, '\n');
  security_note(port: port, extra: r);
}
