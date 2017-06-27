# @DEPRECATED@
#
# Disabled on 2008/11/26. 
exit(0);

#
# (C) Tenable Network Security, Inc.
#

if(description)
{
 script_id(10178);
 script_bugtraq_id(712);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0058");
 script_name(english:"php.cgi buffer overrun");
 
 desc["english"] = "There is a buffer overrun in
the 'php.cgi' CGI program, which will allow anyone to
execute arbitrary commands with the same privileges as the
web server (root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";

 script_description(english:desc["english"]);
 
 script_summary(english:"Checks for the /cgi-bin/php.cgi buffer overrun");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2010 Tenable Network Security, Inc.");
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
port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"php.cgi", port:port);
if(res)
{
 c = string("php.cgi?", crap(32000));
 p2 = is_cgi_installed_ka(item:c, port:port);
 if(p2 == 0)
 {
  security_hole(port);
 }
}
