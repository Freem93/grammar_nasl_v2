#
# This NASL script has been produced as a collaboration between:
#
# - Martin O'Neal of Corsaire (http://www.corsaire.com)  
# - Jakob Bohm of Danware (http://www.danware.dk)
# 
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Neither Corsaire 
# or Danware accept any responsibility for any damage caused by the use or misuse 
# of this information.
# 

# Changes by Tenable:
# - Revised plugin title, output formatting, updated risk (9/8/09)

############## description ################

# declare description

include("compat.inc");

if (description)
{
  script_id(15765);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2012/12/09 02:39:16 $");

  script_name(english:"NetOp Products Detection (TCP)");
  script_summary(english:"Determines if the remote host has any Danware NetOp program active on TCP");

  script_set_attribute(attribute:"synopsis", value:"A remote control software is running on this port.");
  script_set_attribute(attribute:"description", value:
"This script detects if the remote system has a Danware NetOp program
enabled and running on TCP.  These programs are used for remote system
administration, for telecommuting and for live online training.  They
also usually allow authenticated users to access the local system
remotely.");
  script_set_attribute(attribute:"see_also", value:"http://www.netop.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:danware_data:netop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english: "This NASL script is Copyright (C) 2004-2012 Corsaire Limited and Danware Data A/S.");
  script_family(english:"Service detection");
  script_dependencies("find_service1.nasl","find_service2.nasl", "rpcinfo.nasl", "dcetest.nasl");
  script_require_ports(6502, 1971, "Services/unknown");
  exit(0);
}



############## declarations ################

# includes
include('netop.inc');
include('global_settings.inc');

# declare function
function test(port)
{
	local_var socket, banner_pkt;

	if ( ! get_port_state(port) ) return 0;

	# open connection
	socket=open_sock_tcp(port, transport:ENCAPS_IP);
	
	# check that connection succeeded
	if(socket)
	{
		########## packet one of two ##########
		
		# send packet
		send(socket:socket, data:helo_pkt_gen);
	
		# recieve response
		banner_pkt = recv(socket:socket, length:1500, timeout: 3);
    # check response contains correct contents and
		#   log response accordingly.
		netop_check_and_add_banner(port: port, banner_pkt: banner_pkt);
		
		########## packet two of two ##########
		
		if (ord(netop_kb_val[39]) == 0xF8)
		{
			send(socket:socket,data:quit_pkt_stream);
		}
		close(socket);
	}
}


############## script ################

# initialise variables
local_var socket;
addr=get_host_ip();
proto_nam='tcp';

# test default ports
test(port:6502);
test(port:1971);

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
# retrieve and test unknown services
port=get_unknown_svc();
if(!port)exit(0);
if(!get_tcp_port_state(port))exit(0);
if(! service_is_unknown(port:port))exit(0);
test(port:port);
}
exit(0);



############## End of TCP-specific detection script ################

