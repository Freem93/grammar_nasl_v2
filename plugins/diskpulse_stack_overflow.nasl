#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51095);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/24 10:42:16 $");

  script_bugtraq_id(43919);

  script_name(english:"Remote Code Execution in DiskPulse Server");
  script_summary(english:"Test for DiskPulse Server 'GetServerInfo' Buffer Overflow Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:"The remote service has a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"A stack overflow vulnerability exists in the DiskPulse Server
installed on the remote host.

By sending a specially crafted message to the server, a remote
attacker can leverage this vulnerability to execute arbitrary code on
the server with SYSTEM privileges.

Note that Nessus checked for this vulnerability by sending a specially
crafted packet and checking the response, without crashing the
service.

All 2.x versions 2.2 and below are known to be affected, and others
may be as well.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3 as it appears to address the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-633");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies('diskpulse_detect.nasl');
  script_require_ports('Services/diskpulse', 9120);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Get the port
port = get_service(svc:'diskpulse', default:9120, exit_on_fail:TRUE);

# Open the socket
socket = open_sock_tcp(port);
if (!socket) exit(1, "Can't open socket on port "+port+".");


# Build a completely invalid GetServerInfo packet. Basically, we want the 'GetServerInfo'
# header, the \x02 separator, 0x30 bytes to test the overflow (anything between 0x2c and 0x100
# would actually work without crashing), then enough data to pad the packet to 512 bytes.
request = 'GetServerInfo\x02';
request = request + crap(0x30) + '\x02';
request = request + crap(512 - strlen(request));

# Send our packet
send(socket:socket, data:request);

# Receive 512 bytes back (should be 'OK' then 510 bytes of nonsense)
response = recv(socket:socket, length:512, min:512);
if (isnull(response)) exit(0, "The service on port "+port+" failed to respond.");

# If the server returns 'OK', it's vulnerable
if(substr(response, 0, 1) == 'OK')
{
  security_hole(port);
  exit(0);
}
else if(substr(response, 0, 2) == 'ERR')
{
  exit(0, "The DiskPulse Server listening on port "+port+" is not affected.");
}
exit(1, "The DiskPulse Server listening on port "+port+" returned an unexpected result.");


