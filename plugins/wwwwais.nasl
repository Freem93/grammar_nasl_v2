#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10597);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-2001-0223");
 script_bugtraq_id(2292);
 script_osvdb_id(494);

 script_name(english:"wwwwais QUERY_STRING Parameter Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The 'wwwwais' CGI is installed.  This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=97984174724339&w=2" );
 script_set_attribute(attribute:"solution", value:
"Remove the script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/17");
 script_cvs_date("$Date: 2011/03/14 21:48:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/wwwwais");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 r = http_send_recv3(method: "GET", port: port, item: strcat(dir, "/wwwwais?version=123&", crap(4096)), exit_on_fail: 1);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if("memory violation" >< buf)
 {
   security_hole(port);
   exit(0);
 }
}

