#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10790);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
 script_cve_id("CVE-2001-0838");
 script_osvdb_id(660);
 
 script_name(english:"Network Solutions Rwhoisd -soa Command Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote rwhois daemon is vulnerable to a format string
attack when supplied malformed arguments to a '-soa' request.

An attacker may use this flaw to gain a shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Disable this service or upgrade to a patched version" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines if rwhois is vulnerable to a format string attack");
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2013 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rwhois", 4321);
 exit(0);
}

#
# The script code starts here
#

port = 4321;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string("-soa %p\r\n"));
  r = recv(socket:soc, length:4096);
  close(soc);
  if(egrep(pattern:"^%error 340 Invalid Authority Area: 0x.*", 
	  string:r))security_hole(4321);
 }
}
