#
# (C) Tenable Network Security, Inc.
#

# Added some extra checks. Axel Nennker axel@nennker.de

include("compat.inc");

if(description)
{
 script_id(11370);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-1376");
 script_bugtraq_id(2252);
 script_osvdb_id(3500);

 script_name(english:"Microsoft IIS fpcount.exe CGI Remote Overflow");
 script_summary(english:"Is fpcount.exe installed ?");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Nessus detected the 'fpcount.exe' CGI on the remote web server. Some
versions of this CGI have a remote buffer overflow vulnerability. A
remote attacker could exploit it to crash the web server, or possibly
execute arbitrary code.

*** Nessus did not actually check for this flaw, but solely relied on
*** the presence of this CGI instead." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Jan/173"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Make sure FPServer Extensions 98 or later is installed."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/14");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/_vti_bin/fpcount.exe", port:port);
if (isnull(res)) exit(1, "The server didn't respond.");

res = res[0] + res[1] + res[2];
if(("Microsoft-IIS/4" >< res) && ("HTTP/1.1 502 Gateway" >< res) )
	security_hole(port);
