#
# (C) Tenable Network Security, Inc.
#
if ( NASL_LEVEL < 5201 ) exit(0, "webmirror3.nbin is required");

include("compat.inc");

if(description)
{
 script_id(50345);
 script_version ("$Revision: 1.4 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");

 script_name(english: "Missing or Permissive X-Frame-Options HTTP Response Header");
 script_summary(english: "Reports pages that do not use X-Frame-Options headers.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server does not take steps to mitigate a class of web
application vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote web server in some responses sets a permissive
X-Frame-Options response header or does not set one at all.

The X-Frame-Options header has been proposed by Microsoft as a way to
mitigate clickjacking attacks and is currently supported by all major
browser vendors");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Clickjacking");
 # https://software-security.sans.org/blog/2009/10/15/adoption-of-x-frame-options-header/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?399b1f56");
 script_set_attribute(attribute:"solution", value:
"Set a properly configured X-Frame-Options header for all requested
resources.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);
xfo_hdrs = get_kb_list("www/"+port+"/header/missing/x-frame-options");
if (empty_or_null(xfo_hdrs))
 exit(0, "X-Frame-Options response headers were seen from the web server on port "+port+".");

xfo_hdrs = sort(list_uniq(make_list(xfo_hdrs)));
report = '\nThe following pages do not set a X-Frame-Options response header or set a permissive policy:\n\n';
foreach page (xfo_hdrs) report = strcat(report, '  - ', build_url(qs:page, port:port), '\n');
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
exit(0);
