# @DEPRECATED@
#
# Disabled on 2004/02/27. Deprecated by more specific upload CGI test scripts.
exit(0); 

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10290);
 script_version ("$Revision: 1.23 $");
 script_xref(name:"OSVDB", value:"228");
 
 script_name(english:"Upload cgi");
 
 desc["english"] = "The 'upload.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone upload arbitrary
files on the remote web server.

Solution : remove it from /cgi-bin.

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Checks for the presence of /cgi-bin/upload.cgi");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
res = is_cgi_installed_ka(item:"upload.cgi", port:port);
if(res)security_warning(port);
