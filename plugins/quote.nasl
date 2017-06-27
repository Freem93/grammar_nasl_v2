#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (9/17/09)
# - Changed family (10/8/09)


include("compat.inc");

if(description)
{
 script_id(10198);
 script_version ("$Revision: 1.27 $");
 script_cvs_date("$Date: 2011/07/26 22:38:34 $");

 script_cve_id("CVE-1999-0103");
 script_osvdb_id(150);

 script_name(english:"Quote of the Day (QOTD) Service Detection");

 script_set_attribute(attribute:"synopsis", value:
"The quote service (qotd) is running on this host." );
 script_set_attribute(attribute:"description", value:
"A server listens for TCP connections on TCP port 17. Once a connection 
is established a short message is sent out the connection (and any 
data received is thrown away). The service closes the connection 
after sending the quote.

Another quote of the day service is defined as a datagram based
application on UDP.  A server listens for UDP datagrams on UDP port 17.
When a datagram is received, an answering datagram is sent containing 
a quote (the data in the received datagram is ignored).

An easy attack is 'pingpong' which IP spoofs a packet between two machines
running qotd. This will cause them to spew characters at each other,
slowing the machines down and saturating the network." );
 script_set_attribute(attribute:"solution", value:
"- Under Unix systems, comment out the 'qotd' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpQotd
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpQotd
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "1996/02/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the presence of qotd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Mathieu Perrin");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 exit(0);
}
 
#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

if(get_udp_port_state(17))
{		  
 udpsoc = open_sock_udp(17);
 if ( ! udpsoc ) exit(0);
 send(socket:udpsoc, data:'\r\n');
 b = recv(socket:udpsoc, length:1024);
 if(b)
 {
  b = chomp(b);
  if (report_verbosity > 1 && strlen(b) > 0)
   security_note(port:17, protocol: "udp", extra: '\nThe service sent :\n\n', b, '\n');
  else
   security_note(port:17, protocol:"udp");
  register_service(port:17, ipproto:"udp", proto:"qotd");
 }
 close(udpsoc);
}

if(get_port_state(17))
{
 p = known_service(port:17);	# May fork
 if(!p || p == "qotd")
 {
 soc = open_sock_tcp(17);
 if(soc)
  {
    a = recv_line(socket:soc, length:1024);
    if(a)
    {
      a = chomp(a);
      if (report_verbosity > 1 && strlen(a) > 0)
        security_note(port:17, extra: '\nThe service sent :\n\n', a, '\n');
      else
        security_note(17);
      if (!p) register_service(port:17, ipproto:"tcp", proto:"qotd");
    }
    close(soc);
  }
 }
}

