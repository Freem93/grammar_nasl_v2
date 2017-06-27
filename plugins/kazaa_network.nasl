#
# (C) Tenable Network Security, Inc.
#

# there is already a nice Kazaa check by Nessus...however, it relies on registry read 
# access...this check works even without registry access...

include("compat.inc");

if(description)
{
 script_id(11844);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2003-0397");
 script_bugtraq_id(7680);
 script_osvdb_id(57665);

 script_name(english:"FastTrack (FT) Crafted Packet Handling Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
   "The remote peer-to-peer client is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description",  value:
"The remote service seems to be a Kazaa peer-to-peer client.

The FastTrack (FT) network code, as used in Kazaa and possibly other
P2P clients, contains a remotely exploitable flaw in its packet
handling code.  Sending a specially crafted packet with a large list
of supernodes may allow execution of arbitrary code." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2003/May/279"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2003/05/26"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/09/22"
 );
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Determines if the remote system is running Kazaa");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 exit(0);
}




port = 6699;
if(!get_udp_port_state(port))exit(0);
req = raw_string(0x27,0x00,0x00,0x00,0xA9,0x80,0x4B,0x61,0x5A,0x61,0x41,0x00);
soc = open_sock_udp(port);
if (! soc ) exit(0);
send(socket:soc, data:req);
r = recv(socket:soc, length:256);
if (strlen(r) == 21) security_hole(port:port, protocol:"udp");
