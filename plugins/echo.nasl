#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10061);
 script_version ("$Revision: 1.41 $");
 script_cvs_date("$Date: 2014/06/09 20:25:40 $");
 script_cve_id("CVE-1999-0103", "CVE-1999-0635");
 script_osvdb_id(150);

 script_name(english:"Echo Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"An echo service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'echo' service. This service 
echoes any data which is sent to it. 
 
This service is unused these days, so it is strongly advised that
you disable it, as it may be used by attackers to set up denial of
services attacks against this host." );
 script_set_attribute(attribute:"solution", value:
"- Under Unix systems, comment out the 'echo' line in /etc/inetd.conf
  and restart the inetd process
 
- Under Windows systems, set the following registry key to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpEcho
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpEcho
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks if the 'echo' port is open");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


pattern = string("Harmless Nessus echo test");

#
# The script code starts here
#
include("pingpong.inc");

port = get_kb_item("Services/echo");
if(!port)port = 7;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res = recv_line(socket:soc, length:1024);
  if(data == res)
   {
   security_note(port);
   register_service(port:port, proto:"echo");
   }
  close(soc);
  }
}

if(get_udp_port_state(port))
{
 soc = open_sock_udp(port);
 if(soc)
 {
  data = string(pattern, "\r\n");
  send(socket:soc, data:data);
  res2 = recv(socket:soc, length:1024);
  if(res2)
  {
  if(data ==  res2)security_note(port:port, protocol:"udp");
  #  if (udp_ping_pong(port: port, data: data, answer: res2))
      
  }
  close(soc);
 }
}

