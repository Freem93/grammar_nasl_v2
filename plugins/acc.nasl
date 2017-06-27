#
#
# This script was written by Sebastian Andersson <sa@hogia.net>
#

# Changes by Tenable:
# - french description, script id, cve id [RD]
# - changed family (9/6/09)

#
# See the Nessus Scripts License for details
#



include("compat.inc");

if(description)
{
 script_id(10351);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-1999-0383");
 script_bugtraq_id(183);
 script_osvdb_id(267);
 
 script_name(english:"ACC Tigris Access Terminal Configuration Disclosure");
 script_summary(english:"Checks for ACC SHOW command bug");

 script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote router is an ACC Tigris Terminal Server.  Some software
versions on this router will allow an attacker to run the SHOW command
without first providing authentication.  An attacker could exploit
this to read part of the router's configuration. 

In addition there is a 'public' account with a default password of
'public' which would allow an attacker to execute non-privileged
commands on the host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Jan/23" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Jan/32" );
 script_set_attribute(attribute:"solution", value:
"Add access entries to the server to allow access only from authorized
staff." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/03");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Sebastian Andersson");
 script_family(english:"Misc.");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');

port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

banner = get_telnet_banner(port:port);
if ( ! banner) exit(1, "No telnet banner on port "+port+".");
if ("Login:" >< banner ) exit(0, "Invalid telnet banner on port "+port+".");

soc = open_sock_tcp(port);
if (! soc) exit(1, "Could not connect to TCP port "+port+".");

  first_line = telnet_negotiate(socket:soc);
  if("Login:" >< first_line) {
   req = '\x15SHOW\r\n';
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   r = recv_line(socket:soc, length:1024);
   if(("SET" >< r) ||
      ("ADD" >< r) ||
      ("RESET" >< r)) {
    security_warning(port);
    # cleanup the router...
    while("RESET" >!< r) {
     if("Type 'Q' to quit" >< r) {
      send(socket:soc, data:"Q");
      close(soc);
      exit(0);
     }
     r = recv(socket:soc, length:1024);
    }
   }
  }
  close(soc);
