#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10420);
 script_bugtraq_id(1234);
 script_osvdb_id(322);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0437");
 
 script_name(english:"Gauntlet CyberPatrol Content Monitoring System Overflow");
 script_summary(english:"Overflow in the Gauntlet product line.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Network Associated Gauntlet firewall. The
installed version of the software is vulnerable to a buffer overflow.
An attacker could exploit this flaw in order to remotely execute
arbitrary commands on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f69d6a17" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/May/254" );
 script_set_attribute(attribute:"solution", value:
"Apply the workaround or patches from the listed references." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/22");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports(8999);
 exit(0);
}


port = 8999;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

  soc = open_sock_tcp(port);
  if(! soc) exit(1, "TCP connection to port "+port+"failed.");

    req = string("10003.http://", crap(10), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if ( ! r ) exit(0, "No answer from port "+port+".");

    soc = open_sock_tcp(port);
    if ( ! soc ) exit(1, "TCP connection to port "+port+"failed.");
    req = string("10003.http://", crap(10000), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if(!r)
    {
      security_hole(port);
    }
