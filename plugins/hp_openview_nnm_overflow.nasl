#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19707);
  script_version("$Revision: 1.16 $");
  script_cve_id("CVE-2005-1056");
  script_bugtraq_id(13029);
  script_osvdb_id(15321);

  script_name(english:"HP OpenView Network Node Manager Multiple Services Remote Overflow");
  
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
HP OpenView Topology Manager Daemon." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP OpenView Topology Manager Daemon for IP
discovery and layout. 

The remote version of this software has a heap overflow vulnerability. 

An unauthenticated attacker can exploit this flaw by sending a
specialy crafted packet to the remote host.  Successful exploitation
of this vulnerability would result in remote code execution with the
privileges of the daemon itself. 

Note that other OV NNM services are affected by this flaw as well." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/8372" );
 script_set_attribute(attribute:"solution", value:
"Install one of the patches listed in the advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/04/05");
 script_cvs_date("$Date: 2013/06/21 21:39:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
script_end_attributes();

 
  script_summary(english:"Checks for HP OpenView NNM Heap Overflow");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencie("hp_openview_ovtopmd.nasl");
  script_require_ports(2532);
  exit(0);
}

include ("misc_func.inc");

port = get_kb_item('Services/ovtopmd');
if (!port) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

req = raw_string (0x00,0x00,0x3F,0xFD,0x54,0x4E,0x53) + crap(data:raw_string(0), length:0x3FFA);

send (socket:soc, data:req);
buf = recv(socket:soc, length:16);

if ("0000000c000000020000000100000000" >< hexstr(buf))
{
  security_hole(port);
}
