#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#
# @DEPRECATED@
exit(0);	# FPs

# Changes by Tenable:
# - Revised plugin title (4/18/009)

if(description)
{
 script_id(10098);
 script_bugtraq_id(776);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0237");
 script_xref(name:"OSVDB", value:"83");

 script_name(english:"Guestbook CGI Arbitrary Command Execution");

 desc["english"] = "The 'guestbook.cgi' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).

Solution :  remove it from /cgi-bin.

Risk factor : High";

 script_description(english:desc["english"]);

 script_summary(english:"Checks for the presence of /cgi-bin/guestbook.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Mathieu Perrin");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 
 exit(0);
}	  
  
#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"guestbook.cgi", port:port);
if(res)
{
 security_hole(port);
}
   
