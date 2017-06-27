#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14683);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2000-0360");
 script_bugtraq_id(1249);
 script_osvdb_id(1353);
 
 script_name(english:"INN < 2.2.2 Crafted Article Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running INN (InterNetNews).

The remote version of this server does not do proper bounds checking. 
An attacker may exploit this issue to crash the remote service by overflowing
some of the buffers by sending a maliciously formatted news article." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c352440e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.2 of this service or newer" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/24");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks INN version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
    r = recv_line(socket:soc, length:1024);
    if ( r == NULL ) exit(0);
    #check for version 2.0.0 to 2.2.1
    if(egrep(string:r, pattern:"^20[0-9] .* INN 2\.(([0-1]\..*)|(2\.[0-1][^0-9])) .*$"))
    {
      security_warning(port);
    }
  }
}
