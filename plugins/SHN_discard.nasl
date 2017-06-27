#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (9/17/09)
# - Changed family (10/8/09)
# - Updated to use compat.inc (11/20/09)
# - Updated CVSS score (2/23/09)

include("compat.inc");

if(description)
{
 script_id(11367);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");

 script_name(english:"Discard Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A discard service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a 'discard' service.  This service
typically sets up a listening socket and will ignore all the data
which it receives. 

This service is unused these days, so it is advised that you disable
it." );
 script_set_attribute(attribute:"solution", value:
"- Under Unix systems, comment out the 'discard' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpDiscard
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service." );
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks if the 'discard' port is open");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 StrongHoldNet");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports(9);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = 9; # Discard is not supposed to run on any other port.
if(! service_is_unknown(port:port)) { exit(0); }

# We send between 17 and 210 bytes of random data.
# If the service is still listening without any output, we assume
# that 9/tcp is running 'discard'.
function check_discard(soc) {
  local_var i, n, res;
  if(!soc)
   return(0);

  n = send(socket:soc, data:string(crap(length:(rand()%193+17), data:string(rand())),"\r\n\r\n"));
  if (n<0)
   return(0);

  res = recv(socket:soc, length:1024, timeout:5);
  if(strlen(res) > 0)
   return(0);

  return(1);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(check_discard(soc:soc)) {
   security_note(port);
   register_service(port:port,proto:"discard");
   if(soc)
    close(soc);
 }
}

exit(0);
