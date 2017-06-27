#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11974);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(9316);
 script_osvdb_id(3257);
 script_xref(name:"Secunia", value:"2694");

 script_name(english:"Jordan's Windows Telnet Server Password Handling Remote Overflow");
 script_summary(english:"Determines the version of the remote telnet server");

 script_set_attribute(attribute:"synopsis",  value:
"The remote telnet server has a stack-based buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Jordan's Windows Telnet Server
running on the remote host has a stack-based buffer overflow
vulnerability in the login procedure.  A remote attacker could exploit
this to crash the service, or execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://aluigi.altervista.org/adv/jordwts-adv.txt"
 );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.  It appears this application
is no longer actively maintained.  Disable this service." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/29");
 script_cvs_date("$Date: 2014/05/30 21:51:49 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);

 exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
r = get_telnet_banner(port:port);
if(!r)exit(0);
if ( "Windows Telnet Server Version 1." >< r ) security_hole(port);
