#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19946);
 script_version("$Revision: 1.12 $");

 script_bugtraq_id(9039, 13037);
 script_osvdb_id(2814, 15354);

 script_name(english:"WebWasher < 4.4.1 Build 1613 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web proxy suffers from multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the web proxy WebWasher.

According to its banner, the installed version of WebWasher is prone to
multiple cross-site scripting flaws.  Successful exploitation of these
issues may allow an attacker to execute malicious script code in a
user's browser within the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/WebWasherXSS.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/wwcsm.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebWasher CSM 4.4.1 Build 1613 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/13");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of WebWasher Proxy");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080, 9090);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9090);

if(!get_port_state(port))exit(0);

req = http_get(item:"/nessus345678.html", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
if( r == NULL )exit(0);

if ( ("<title>WebWasher - " >< r))
{
 if (egrep(pattern:"generated .* by .* \(WebWasher ([0-3]\..*|4\.([0-3] .*|4\.1 .uild ([0-9][0-9][0-9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-2])))))\)", string:r))
 {
   security_warning(port);
   set_kb_item(name: 'www_proxy/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}
