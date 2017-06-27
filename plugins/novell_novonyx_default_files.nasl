#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)


include("compat.inc");

if(description)
{
  script_id(12049);
  script_version ("$Revision: 1.17 $");
  script_cve_id("CVE-2002-1634");
  script_bugtraq_id(4874);
  script_osvdb_id(17461, 17462, 17463, 17464, 17465, 17466, 17467, 17468);

  script_name(english:"Novonyx Web Server Multiple Sample Application Files Present");
 
 script_set_attribute(attribute:"synopsis", value:
"Default files are installed on this system." );
 script_set_attribute(attribute:"description", value:
"Novell NetWare default Novonyx web server files.

A default installation of Novell 5.x will install the Novonyx web server. 
Numerous web server files included with this installation could reveal system 
information." );
 script_set_attribute(attribute:"solution", value:
"If not required, remove all default Novonyx web server files." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/30");
 script_cvs_date("$Date: 2011/03/17 17:53:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for default Novonyx web server files");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 David Kyger");
 script_family(english:"Netware");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


flag = 0;

warning = "
The following Novonyx web server files were found on the server:";

port = get_http_port(default:80);

if(get_port_state(port)) {

   pat1 = "NetBasic WebPro Demo";
   pat2 = "Novell";
   pat3 = "ScriptEase:WSE";
   pat4 = "ALLFIELD.JSE";
   pat5 = "LAN Boards";
   pat6 = "Media Type";
   pat7 = "Login to NDS";
   pat8 = "Total Space";
   pat9 = "Free Space";
   pat10 = "SERVER_SOFTWARE";
   pat11 = "GATEWAY_INTERFACE";
   pat12 = "ADMSERV_ROOT";
   pat13 = "ADMSERV_PWD";
   pat14 = "Directory Listing Tool";
   pat15 = "Server Name";
   pat16 = "Source directory";
   pat17 = "secure directories sys";

   fl[0] = "/netbasic/websinfo.bas";
   fl[1] = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/allfield.jse";
   fl[2] = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/test.jse";
   fl[3] = "/perl/samples/lancgi.pl";
   fl[4] = "/perl/samples/ndslogin.pl";
   fl[5] = "/perl/samples/volscgi.pl";
   fl[6] = "/perl/samples/env.pl";
   fl[7] = "/nsn/env.bas";
   fl[8] = "/nsn/fdir.bas";

 
   for(i=0;fl[i];i=i+1) 
   { 
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat2 >< buf) || (pat8 >< buf && pat9 >< buf) || (pat10 >< buf && pat11 >< buf) || (pat12 >< buf && pat13 >< buf) || (pat14 >< buf && pat15 >< buf) || (pat16 >< buf && pat17 >< buf)) {
        warning = warning + string("\n", fl[i]); 
        flag = 1;
        }
   }
    if (flag > 0) {
        security_warning(port:port, extra:warning);
        } else {
          exit(0);
        }
}
