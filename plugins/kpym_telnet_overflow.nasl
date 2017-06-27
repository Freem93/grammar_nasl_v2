#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11983);
 script_version ("$Revision: 1.12 $");

 script_bugtraq_id(9379);
 script_osvdb_id(3347);
 
 script_name(english:"KpyM Telnet Server DoS");
 script_summary(english:"Determines the version of the remote telnet server");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote telnet server is prone to a denial of service attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is running KpyM Telnet Server, a Telnet server for
Windows. 

According to its banner, the installed version of KpyM is older than
1.06.  Such versions mark a connection as free before all components,
such as sockets and threads, are shut down.  By flooding the service
with connections, an attacker can cause the service to crash."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://norpius.altervista.org/kpymen.htm"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to version 1.06 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2004/01/02"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2004/01/03"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/01/07"
 );
 script_cvs_date("$Date: 2011/03/21 01:44:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(get_port_state(port))
{
  r = get_telnet_banner(port:port);
  if(!r)exit(0);
  if ( egrep(pattern:"KpyM Telnet Server v(0\.|1\.0[0-5][^0-9])",
	     string:r))security_warning(port);
}
