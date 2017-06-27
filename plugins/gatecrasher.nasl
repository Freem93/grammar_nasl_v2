#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10093);
 script_version ("$Revision: 1.24 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");

 script_name(english:"GateCrasher Backdoor Detection");
 script_summary(english:"Checks for the presence of GateCrasher");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a backdoor installed." );
 script_set_attribute(attribute:"description", value:
"The remote host has the backdoor GateCrasher installed. This backdoor
allows anyone to partially take control of the affected system. An
attacker may use it to steal information or crash the affected host." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this host on port 6969, then type 'gatecrasher;', without the
quotes, and press Enter. Then type 'uninstall;' and press Enter." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl");
 script_require_ports(6969);
 exit(0);
}

#
# The script code starts here
#

port = 6969;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  a = recv(socket:soc, length:40);
  if("GateCrasher" >< a)security_hole(port);
  close(soc);
 }
}
