#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10640);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/04/28 18:42:40 $");

 script_cve_id("CVE-2002-2443");
 script_osvdb_id(93240);

 script_name(english:"Kerberos Server Spoofed Packet Amplification DoS (PingPong)");
 script_summary(english:"Checks for the presence of a bad krb server");

 script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Kerberos server that seems to be
vulnerable to a 'ping-pong' attack. 

When contacted on the UDP port, this service always responds, even to
malformed requests.  This makes it possible to involve it in a
'ping-pong' attack, in which an attacker spoofs a packet between two
machines running this service, causing them to spew characters at each
other, slowing the machines down and saturating the network.");
 script_set_attribute(attribute:"solution", value:"Upgrade to krb5-1.11.3 or later. Additionally, you can disable this service if it is not required.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1996/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/25");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q2/316");
 script_set_attribute(attribute:"see_also", value:"htp://krbdev.mit.edu/rt/Ticket/Display.html?id=7637");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 exit(0);
}
 

if(!get_udp_port_state(464))exit(0);

soc = open_sock_udp(464);
crp = crap(25);
if(soc)
{
 send(socket:soc, data:crp);
 r = recv(socket:soc, length:255);
 if(r){
	send(socket:soc, data:r);
	r = recv(socket:soc, length:255);
	if ( r ) security_hole(port:464, protocol:"udp");
     }
}
