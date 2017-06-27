#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11765);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");
 
 script_name(english:"UPnP TCP Helper Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running Microsoft UPnP TCP 
helper." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft UPnP TCP helper.

If the tested network is not a home network, you should 
disable this service." );
 script_set_attribute(attribute:"solution", value:
"Set the following registry key :
   Location : HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV
   Key      : Start
   Value    : 0x04" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"UPnP/tcp scan");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(5000);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);

if(get_port_state(5000))
{
 soc = open_sock_tcp(5000);
 if( !soc)exit(0);
 send(socket:soc, data:'\r\n\r\n');
 r = recv_line(socket:soc, length:4096);
 if("HTTP/1.1 400 Bad Request" >< r) 
 {
 	security_note(5000);
 }
}
