#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10045);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0889");
 script_osvdb_id(39);
 script_name(english:"Cisco 675 Router Default Unpassworded Account");
 script_summary(english:"Logs into the remote CISCO router");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router is not secured with a password."
 );
 script_set_attribute( attribute:"description",  value:
"The remote CISCO router is not secured with a password. A remote 
attacker could log in and take complete control of this device." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Aug/5"
 );
 # https://web.archive.org/web/20021028095615/http://www.cisco.com/en/US/products/hw/modems/ps296/products_installation_guide_chapter09186a008007dd70.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?db507938"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Login to this router and set a strong password."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/07/31");
 script_cvs_date("$Date: 2017/05/10 19:18:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:675_router");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");
 
 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");
 script_require_ports(23);
 
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');

port = 23;
if(get_port_state(port))
{
 buf = get_telnet_banner(port:port);
 if ( ! buf || "User Access Verification" >!< buf ) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("User Access Verification" >< buf)
  {
   buf = recv(socket:soc, length:1024);
   data = string("\r\n");
   send(socket:soc, data:data);
   buf2 = recv(socket:soc, length:1024);
   if(">" >< buf2)security_hole(port);
  }
 close(soc);
 }
}
