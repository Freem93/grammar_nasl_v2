#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10754);
 script_cve_id("CVE-1999-0508");
 script_osvdb_id(625);
 script_version ("$Revision: 1.20 $");
 
 script_name(english:"Cisco Multiple Devices Unpassworded Account");
 script_summary(english:"Checks for the absence of a password");

 script_set_attribute( attribute:"synopsis", value:
"It is possible to login to the remote network device without a
password." );
 script_set_attribute( attribute:"description",  value:
"The remote host appears to be a Cisco router or switch with no
password set.  This can allow a remote attacker to login to the device
and take control of it." );
 script_set_attribute( attribute:"solution",  value:
"Login and set exec and enable passwords.  For more information, refer
refer to the manual for the device." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/01");
 script_cvs_date("$Date: 2016/08/29 13:57:36 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}


include('telnet_func.inc');

function test_cisco(password, port)
{
 local_var soc, r;

 soc = open_sock_tcp(port);

 if(soc)
 {
  r = telnet_negotiate(socket:soc);
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string(password, "\r\n"));
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string("show ver\r\n"));
  r = recv(socket:soc, length:4096);
  if("Cisco Internetwork Operating System Software" >< r)
  {
   security_hole(port);
   set_kb_item(name: 'CISCO/no_passwd/'+port, value: TRUE);
  }
  close(soc);
 }
}


port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "User Access Verification" >!< banner ) exit(0);


test_cisco(password:"", port:port);
