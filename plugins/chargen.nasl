#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, family change (9/17/09)
# - Minor description touch-ups (9/14/10)

include("compat.inc");

if(description)
{
 script_id(10043);
 script_version ("$Revision: 1.37 $");
 script_cvs_date("$Date: 2014/04/23 16:40:39 $");

 script_cve_id("CVE-1999-0103");
 script_osvdb_id(150);

 script_name(english:"Chargen UDP Service Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a 'chargen' service." );
 script_set_attribute(attribute:"description", value:
"When contacted, chargen responds with some random characters (something
like all the characters in the alphabet in a row). When contacted via UDP, it
will respond with a single UDP packet. When contacted via TCP, it will
continue spewing characters until the client closes the connection.

The purpose of this service was to mostly test the TCP/IP protocol
by itself, to make sure that all the packets were arriving at their
destination unaltered. It is unused these days, so it is suggested
you disable it, as an attacker may use it to set up an attack against
this host, or against a third-party host using this host as a relay.

An easy attack is 'ping-pong' in which an attacker spoofs a packet between
two machines running chargen. This will cause them to spew characters at
each other, slowing the machines down and saturating the network." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0dbdf05" );
 script_set_attribute(attribute:"solution", value:
"- Under Unix systems, comment out the 'chargen' line in /etc/inetd.conf
  and restart the inetd process

- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen

 Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp

To restart the service." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Chargen Probe Utility');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "1996/02/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of chargen");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Mathieu Perrin");
 script_family(english:"Denial of Service");
 script_dependencie("find_service1.nasl");

 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("pingpong.inc");


if(get_udp_port_state(19))
{		  
 udpsoc = open_sock_udp(19);
 if ( ! udpsoc ) exit(0);
 data = string("\r\n");
 send(socket:udpsoc, data:data);
 b = recv(socket:udpsoc, length:1024);
 if(strlen(b) > 255)security_warning(port:19,protocol:"udp");
 
 close(udpsoc);
}

if(get_port_state(19))
{
 p = known_service(port:19);	# May fork
 if(!p || p == "chargen")
 {
 soc = open_sock_tcp(19);
 if(soc)
  {
    a = recv(socket:soc, length:255, min:255);
    if(strlen(a) > 255)security_warning(19);
    close(soc);
  }
 }
}

		
