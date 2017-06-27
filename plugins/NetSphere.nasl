#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10005);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");

 script_name(english:"NetSphere Backdoor Detection");
 script_summary(english:"Checks for the presence of NetSphere");

 script_set_attribute(attribute:"synopsis",value:
"A remote host contains a remote access trojan or backdoor." );
 script_set_attribute(attribute:"description", value:
"The NetSphere backdoor is installed on the remote host.  By connecting
to it, a remote attacker can gain control of the affected system." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.commodon.com/threat/threat-ns.htm"
 );
 script_set_attribute(attribute:"solution", value:
"Telnet to TCP port 30100 on the affected host, type '<KillServer>'
(without the quotes), and then press '<Enter>'.  This will stop the
NetSphere service. Then manually determine how the machine came to be
configured with a backdoor and clean it accordingly." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");

 script_family(english:"Backdoors");
 script_dependencie("find_service1.nasl");
 script_require_ports(30100);
 exit(0);
}

#
# The script code starts here
#

port = 30100;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  a = recv_line(socket:soc, length:40);
  if("NetSphere" >< a)security_hole(port);
  close(soc);
 }
}
