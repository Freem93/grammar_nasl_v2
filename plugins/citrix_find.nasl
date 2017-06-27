# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10942);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/06/06 18:48:43 $");

 script_bugtraq_id(7276);
 script_osvdb_id(50616);

 script_name(english:"Citrix Server Detection");
 script_summary(english:"CITRIX check");

 script_set_attribute(attribute:"synopsis", value:
"A Citrix server is running on this machine.");
 script_set_attribute(attribute:"description", value:
"Citrix servers allow a Windows user to remotely obtain a graphical
login (and therefore act as a local user on the remote host).

NOTE: by default the Citrix Server application utilizes a weak 40 bit
obfuscation algorithm (not even a true encryption).  If the default
settings have not been changed, there are tools that can be used to
passively discover userIDs and passwords as they traverse a network.

If this server is located within your DMZ, the risk is substantially
higher, as Citrix necessarily requires access into the internal
network for applications like SMB browsing, file sharing, email
synchronization, etc.

If an attacker gains a valid login and password, this service could be
used to gain further access on the remote host or remote network. This
protocol has also been shown to be vulnerable to a man-in-the-middle
attack.");
 script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/");
 script_set_attribute(attribute:"solution", value:
"Make sure that the server is configured to utilize strong encryption.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/20");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2014 John Lampe...j_lampe@bellsouth.net");
 script_family(english: "Service detection");
 script_require_ports(1494);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");


function check_setting(port) {
 local_var r, soc;

 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(soc) {
    r = recv(socket:soc, length:64);
    if ((egrep(pattern:".*ICA.*", string:r))) {
        security_note(port);
	if (service_is_unknown(port: port))
	  register_service(port: port, proto: "citrix");
    }
    close(soc);
 }
}

port = 1494;
check_setting(port:port);
