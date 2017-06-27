#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
   script_id(10530);
   script_cve_id("CVE-2001-1424");
   script_bugtraq_id(2568);
   script_osvdb_id(429);
   script_version ("$Revision: 1.15 $");
   script_name(english:"Alcatel ADSL Modem Unpassworded Access");
   script_summary(english:"Logs into the remote Alcatel ADSL modem");

 script_set_attribute(attribute:"synopsis", value:
"The remote modem has an account with no password set." );
 script_set_attribute(attribute:"description", value:
"The remote Alcatel ADSL modem has no password set.

An attacker could telnet to this modem and reconfigure it to lock 
you out. This could prevent you from using your Internet connection." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this modem and set a strong password immediately." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/11");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}

port = 23; # alcatel's ADSL modem telnet module can't bind to something else

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:160);
   if("User : " >< r)
   {
     s = string("\r\n");
     send(socket:soc, data:s);
     r = recv(socket:soc, length:2048);
     if("ALCATEL ADSL" >< r)security_hole(port);
   }
   close(soc);
 }
}
