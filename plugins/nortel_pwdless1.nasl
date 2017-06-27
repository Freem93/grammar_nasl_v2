#
# This script was written by Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/2/09)


include("compat.inc");

if(description)
{
   script_id(10528);
   script_version ("$Revision: 1.13 $");
   script_cvs_date("$Date: 2013/01/25 01:19:09 $");

   script_name(english:"Nortel Networks Router Unpassworded Account (manager Level)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is reachable without any password." );
 script_set_attribute(attribute:"description", value:
"The remote Nortel Networks (former Bay Networks) router has
no password for the manager account. 

An attacker could telnet to the router and reconfigure it to lock 
you out of it. This could prevent you from using your Internet 
connection." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this router and set a password immediately." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

   script_summary(english:"Logs into the remote Nortel Networks (Bay Networks) router");
   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2000-2013 Victor Kirhenshtein");
   script_family(english:"Misc.");
   script_require_ports(23);
   exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   buf = get_telnet_banner(port:port);
   if ( ! buf || "Bay Networks" >!< buf ) exit(0);
   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if("Bay Networks" >< buf)
      {
         if ("Login:" >< buf)
         {
            data = string("Manager\r\n");
            send(socket:soc, data:data);
            buf2 = recv(socket:soc, length:1024);
            if("$" >< buf2) security_hole(port);
         }
      }
      close(soc);
   }
}
