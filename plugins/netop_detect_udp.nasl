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
  script_id(15766);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2012/12/09 02:39:16 $");

  script_name(english:"NetOp Products Detection (UDP)");
  script_summary(english:"Determines if the remote host has any Danware NetOp program active on UDP");

  script_set_attribute(attribute:"synopsis", value:"A remote control software is running on this port.");
  script_set_attribute(attribute:"description", value:
"This script detects if the remote system has a Danware NetOp program
enabled and running on UDP.  These programs are used for remote system
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
  script_copyright(english: "This script is Copyright (C) 2004-2012 Corsaire Limited and Danware Data A/S.");
  script_family(english:"Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "rpcinfo.nasl", "dcetest.nasl");
  exit(0);
}



############## declarations ################

# includes
include('global_settings.inc');
include('netop.inc');

# declare function
function test(port)
{
  local_var	socket, banner_pkt;
  if ( ! get_udp_port_state(port) || 
       ! service_is_unknown(port: port, ipproto: 'udp')) return;

	# open connection
	socket=open_sock_udp(port);
	
	# check that connection succeeded
	if(socket)
	{
		########## packet one of one ##########
		
		# send packet
	  	send(socket:socket,data:helo_pkt_udp);
	
		# recieve response
		banner_pkt = recv(socket:socket, length:1500, timeout: 3);
		
		close(socket);
	    	
		# check response contains correct contents and
		#   log response accordingly.
		
		netop_check_and_add_banner(port: port, banner_pkt: banner_pkt);
	}
}



############## script ################

# initialise variables
addr=get_host_ip();
proto_nam='udp';

# test default ports
test(port:6502);
test(port:1971);

if ( thorough_tests )
{
 # retrieve and test unknown services
 ports = get_kb_list("Ports/udp/*");
 if ( isnull(ports) ) exit(0);
 foreach port (keys(ports))
 {
 	port = int ( port - "Ports/udp/" );
	test(port:port);
 }
}

exit(0);



############## End of UDP-specific detection script ################

