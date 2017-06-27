#
# IRC bot ident server detection
# Created: 9/22/04
# Last Updated: 11/25/04
#
# Author: Brian Smith-Sweeney (brian@smithsweeney.com)
# http://www.nessus.org/u?fcee1d3c
#
#
# See the Nessus Scripts License for details
#
# Revision History:
# v1.1 - first released version
# v1.2
#  * Registered security_hole on "port" variable instead of static 113
#  * Made socket timeouts and pause between socket connections variable
#  * Changed default socket timeout to 5 seconds to deal with bots that 
#    refuse connections in quick succession (NOTE: 10 seconds is the most 
#    accurate I've seen, but it makes the test *much* slower)
#

include("compat.inc");

if(description)
{
	script_id(14841);
	script_version ("$Revision: 1.14 $");
	script_cvs_date("$Date: 2013/01/25 01:19:08 $");
	name["english"] = "IRC Bot ident Server Detection";
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"This host seems to be running an ident server, but the ident server responds 
to an empty query with a random userid.  This behavior may be indicative of an
IRC bot, worm and/or virus infection. It is very likely this system has 
been compromised." );
 script_set_attribute(attribute:"solution", value:
"Disinfect or re-install the remote system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

	summary["english"] = "Determines the presence of a malicious ident server";
	family["english"] = "Backdoors";
	script_name(english:name["english"]);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

	script_summary(english:summary["english"]);
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2004-2013 Brian Smith-Sweeney");
	script_family(english:family["english"]);
	script_require_ports("Services/auth", 113);
	script_dependencies("find_service1.nasl");
	exit(0);
}

#
# User-defined variables
#
soc_out=3; # Socket connect timeout; increase this for slow ident bots
soc_sleep=5; # Time to wait between socket connections; increase this for bots
             # that don't respond to multiple requests in quick secession
r='\r\n';  # Data to send to the auth server at initial connect

#
# End user-defined variables; you should not have to touch anything below this 
#
include("global_settings.inc");
include('misc_func.inc');

port = get_kb_item("Services/auth");
if(! port) port = 113;
if (! get_port_state(port)) exit(0);


# Get first response
soc1 = open_sock_tcp(port);
if (! soc1) {
	exit(0);
}
if (send(socket:soc1, data:r)<= 0) exit(0);
r1 = recv_line(socket:soc1,length:1024,timeout:soc_out);
ids1 = split(r1, sep: ':');
if ("USERID" >< ids1[1]) {
	close(soc1);
	sleep(soc_sleep);
	# Get second response
	soc2 = open_sock_tcp(port);
	if (! soc2) {
#Uncomment for debugging	display("oops, can't open the second socket\n");
		exit(0);
	}
	send(socket:soc2, data:r);
	r2 = recv_line(socket:soc2,length:1024,timeout:soc_out);
	ids2 = split(r2, sep: ':');
	close(soc2);
	if ("USERID" >< ids2[1]){
		if (ids1[3]==ids2[3]){
			exit(0);
		}
		security_hole(port);
		if (service_is_unknown(port: port)) 
		  register_service(port: port, proto: 'fake-identd');
		set_kb_item(name: 'fake_identd/'+port, value: TRUE);
		set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
		exit(0);
	}
}
else close(soc1);
