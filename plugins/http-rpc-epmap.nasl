#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (10/12/09)


include("compat.inc");

if(description)
{
 script_id(10763);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2011/03/11 21:52:34 $");

 script_name(english:"HTTP RPC Endpoint Mapper (http-rpc-epmap) Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the http-rpc-epmap service." );
 script_set_attribute(attribute:"description", value:
"This detects the http-rpc-epmap service by connecting
to the port 593 and processing the buffer received.

This endpoint mapper provides CIS (COM+ Internet Services)
parameters like port 135 (epmap) for RPC." );
 script_set_attribute(attribute:"solution", value:
"Deny incoming traffic from the Internet to TCP port 593
as it may become a security threat in the future, if a
vulnerability is discovered." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52ddaa06" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Detect http-rpc-epmap");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Alert4Web.com");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/http-rpc-epmap", 593);
 exit(0);
}

#
# The script code starts here
#

exit(0); # Broken at this time

port = get_kb_item("Services/http-rpc-epmap");
if (!port) port = 593;
key = string("http-rpc-epmap/banner/", port);
banner = get_kb_item(key);

if(!banner)
{
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
  {
  banner = recv(socket:soc, length:1000);
  close(soc);
  }
 }
}

if( "ncacn_http" >< banner)
{
 security_note(port:port);
}
