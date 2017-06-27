#
# (C) Tenable Network Security, Inc.
#
if ( NASL_LEVEL < 5201 ) exit(0, "webmirror3.nbin is required");

include("compat.inc");

if(description)
{
 script_id(50344);
 script_version ("$Revision: 1.3 $");
 script_cvs_date("$Date: 2016/04/14 16:27:23 $");

 script_name(english: "Missing or Permissive Content-Security-Policy HTTP Response Header");
 script_summary(english: "Reports pages that do not set Content-Security-Policy.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server does not take steps to mitigate a class of web
application vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote web server in some responses sets a permissive
Content-Security-Policy (CSP) response header or does not set one at
all.

The CSP header has been proposed by the W3C Web Application Security
Working Group as a way to mitigate cross-site scripting and
clickjacking attacks.");
 script_set_attribute(attribute:"see_also", value:"http://content-security-policy.com/");
 script_set_attribute(attribute:"see_also", value:"https://www.w3.org/TR/CSP2/");
 script_set_attribute(attribute:"solution", value:
"Set a properly configured Content-Security-Policy header for all
requested resources.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);
csp_fa = get_kb_list("www/"+port+"/header/missing/csp-frame-ancestors");
if (empty_or_null(csp_fa))
 exit(0, "Content-Security-Policy response headers were seen from the web server on port "+port+".");

csp_fa = sort(list_uniq(make_list(csp_fa)));
report = '\nThe following pages do not set a Content-Security-Policy response header or set a permissive policy:\n\n';
foreach page (csp_fa) report = strcat(report, '  - ', build_url(qs:page, port:port), '\n');
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
exit(0);
