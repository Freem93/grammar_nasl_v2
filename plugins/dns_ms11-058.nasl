#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55883);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/11/04 02:28:17 $");

  script_cve_id("CVE-2011-1966");
  script_bugtraq_id(49012);
  script_osvdb_id(74399);
  script_xref(name:"MSFT", value:"MS11-058");

  script_name(english:"MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (remote check)");
  script_summary(english:"Checks if Dns.exe on Windows Server 2008 handles long NAPTR lookup requests safely.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The DNS server running on the remote host is affected by a memory
corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows DNS server running on the remote host has a
memory corruption vulnerability that can be triggered by making a
specially crafted NAPTR query.  This could allow an attacker to write
arbitrary data to the heap and potentially execute arbitrary code.

Note that upstream servers may filter this request, creating a false
negative, or may be vulnerable themselves, creating a false positive.
If the target is patched and shows up as vulnerable, check your
upstream DNS servers.

Note also that while Microsoft's advisory referenced multiple
vulnerabilities, Nessus only tests for the vulnerability described
above."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-058");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("dns_server.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/dns");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("dns_func.inc");

# Figure out which port we're using
port = get_service(svc:'dns', default:53, exit_on_fail:TRUE, ipproto:"udp");
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

# Make sure this is Windows 2008 (if possible) before trying
os = get_kb_item("Host/OS");
if (!isnull(os) && '2008' >!< os)
  exit(1, "This plugin only detects vulnerable installations of Windows 2008");

# Connect to the host
s = open_sock_udp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port, "UDP");

# Generate a random transaction id
transaction_id = rand() % 0xFFFF;

# Create a simple DNS packet
dns  = '';
dns += mkword(transaction_id); # Transaction id
dns += mkword(0x0100); # Flags (0x0100 = 'recursion desired')
# Questions, answers, authority, and additional
dns += mkword(0x0001) + mkword(0x0000) + mkword(0x0000) + mkword(0x0000);
dns += '\x08ms11-058\x01t\x06nessus\x03org\x00'; # Using ms11-058.t.nessus.org
dns += mkword(0x0023); # Type (0x0023 = NAPTR)
dns += mkword(0x0001); # Class (0x0001 = IN)
if(!send(socket:s, data:dns))
  exit(1, "Failed to send data to the DNS server listening on UDP port "+port+".");

# Receive the response from the DNS server
response = recv(socket:s, length:0xFFFF);
if(isnull(response))
  exit(1, "Failed to receive a packet from the DNS server listening on UDP port "+port+".");

# Parse the response with the DNS library
dns = dns_split(response);

if(isnull(dns))
  exit(1, "Failed to parse the response from the DNS server listening on UDP port "+port+".");

# Validate the transaction id
if(dns['transaction_id'] != transaction_id)
  exit(1, "Incorrect transaction_id on the response from the DNS server listening on UDP port "+port+".");

# Validate the flags
if(dns['flags'] & 0x0002)
  exit(0, "The response from the DNS server listening on UDP port "+port+" indicates an error; host either isn't vulnerable, it isn't configured to forward DNS requests recursively, or an upstream DNS server prevented the attack.");

i = 0;
while(!isnull(dns['an_rr_data_' + i + '_data']))
{
  # The answer that we get from a vulnerable server is a little complicated,
  # but is fortunately static. It's the in-memory representation of the domain
  # name, as generated by _Name_PacketNameToCountName(), which is a byte
  # representing the number of fields, followed by the length-prefixed fields
  # (ie, test.tenable.com becomes \x03 (number of fields) \x04 (length) "test"
  # \x07 (length) "tenable" \x03 (length) "com" \x00).
  answer = dns['an_rr_data_' + i + '_data'];
  if('\x00\x64' + # Order (the proper value)
     '\x00\x0A' + # Preference (the proper value)
     '\x12' + # Flags length (not the proper value)
     '\x03\x04test\x07tenable\x03com\x00' # encoded name
     >< answer)
  {
    security_hole(port:port, proto:"udp");
    exit(0);
  }
  i++;
}

audit(AUDIT_HOST_NOT, 'affected');
