#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10501);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);
 
 script_name(english: "Trinity v3 Trojan Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trinity v3, a Trojan Horse that 
can be used to control your system or make it attack another network
(this is  actually called a Distributed Denial Of Service attack tool).

It is very likely that this host has been compromised" );
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local
authorities" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detects the presence of trinity v3");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_ports(33270);
 
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(33270))
{
 soc = open_sock_tcp(33270);
 if(soc)
 {
  req = string("!@#\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  req = string("id\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if("uid" >< r)security_hole(33270);
  close(soc);
 }
}
