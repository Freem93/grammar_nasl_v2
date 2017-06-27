#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10341);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0225");
 script_bugtraq_id(1032);
 script_osvdb_id(259);
 
 script_name(english:"Pocsag POC32 Remote Service Default Password (password)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server gives access to protected data." );
 script_set_attribute(attribute:"description", value:
"It is possible to log into the remote pocsag service and view the 
streams of decoded pager messages using the password 'password'.

An attacker may use this problem to gain some knowledge about the 
computer user and then trick him by social engineering." );
 script_set_attribute(attribute:"solution", value:
"Change the password to a random one, or filter incoming connections to
this port" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/12");
 script_cvs_date("$Date: 2015/10/09 22:45:48 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"default_account", value:"true");
script_end_attributes();

 script_summary(english: "log in using password 'password'");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports(8000);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 8000;

if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ( ! buf || "Remote Access" >!< buf ) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  r = telnet_negotiate(socket:soc);
  if("Remote Access" >< r)
   {
   data = string("password\r\n");
   send(socket:soc, data:data);
   
   b = recv_line(socket:soc, length:1024);
   while(b)
   {
   if("Password accepted." >< b)
   {
    security_warning(port);
    close(soc);
    exit(0);
    }
   b = recv_line(socket:soc, length:1024);
  }
  close(soc);
  }
 }
}
