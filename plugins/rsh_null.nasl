#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10096);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
 script_cve_id("CVE-1999-0180");
 script_osvdb_id(11523);

 script_name(english:"rsh NULL Login Remote Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on this host." );
 script_set_attribute(attribute:"description", value:
"It is possible to execute arbitrary command on this host
using rsh by supplying a NULL username." );
 script_set_attribute(attribute:"solution", value: "Configure rsh properly or disable it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/03/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "attempts to log in using rsh");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2013 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("find_service1.nasl", "rsh.nasl");
 script_require_ports("Services/rsh", 514);
 script_require_keys("rsh/active");
 exit(0);
}



port = get_kb_item("Services/rsh");
if(!port)port = 514;
if(!get_port_state(port))exit(0);

soc = open_priv_sock_tcp(dport:port);
if(soc)
{
 s1 = raw_string(0);
 s2 = raw_string(0) +  raw_string(0) + "id" + raw_string(0);
 send(socket:soc, data:s1);
 send(socket:soc, data:s2);
 a = recv(socket:soc, length:1024, min:1);
 if(strlen(a) == 0)exit(0);
 a += recv(socket:soc, length:1024);
 if("uid=" >< a )
 {
  a = str_replace(find:raw_string(0), replace:"", string:a);
  security_hole(port:port, extra:'The command "id" produced the following output:\n' + a);
  set_kb_item(name: 'rsh/null/'+port, value: TRUE);
 }
 close(soc);
}
