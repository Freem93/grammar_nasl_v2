#
#
# This script was written by Giovanni Fiaschi <giovaf@sysoft.it>
#
# See the Nessus Scripts License for details
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID.  
#
# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Changed formatting and removed French (3/26/2009)
# - Revised title (12/22/2008)


include("compat.inc");

if (description)
{
   script_id(10714);
   script_version("$Revision: 1.29 $");
   script_cvs_date("$Date: 2014/05/21 17:27:25 $");

   script_cve_id("CVE-1999-0571");
   script_bugtraq_id(3161);
   script_osvdb_id(592, 1098, 1570);
   
   script_name(english:"ZyXEL Router Default Telnet Password Present");
   script_summary(english:"Logs into the ZyXEL router");

   script_set_attribute(attribute:"synopsis", value:
"The remote host is a router with its default password set.");
   script_set_attribute(attribute:"description", value:
"The remote host is a ZyXEL router with a default password. An attacker could
telnet to it and reconfigure it to lock the owner out and prevent him from
using his Internet connection, or create a dial-in user to connect directly
to the LAN attached to it.");
   script_set_attribute(attribute:"solution", value:
"Telnet to this router and set a password immediately.");
   script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
   script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
   script_set_attribute(attribute:"exploit_available", value:"true");

   script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/13");
   script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");

   script_set_attribute(attribute:"plugin_type", value:"remote");
   script_end_attributes();

   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001-2014 Giovanni Fiaschi");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}


port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:8192);
   if ( "Password:" >!< r ) exit(0);
   s = string("1234\r\n");
   send(socket:soc, data:s);
   r = recv(socket:soc, length:8192);
   close(soc);
   if("ZyXEL" >< r || "ZyWALL" >< r )security_hole(port:port, extra:'\nAfter logging in using the password "1234", Nessus read this :\n\n  ' + r + '\n');
 }
}
