#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(54585);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/07/11 22:13:38 $");

  script_cve_id("CVE-2011-1248");
  script_bugtraq_id(47730);
  script_osvdb_id(72234);
  script_xref(name:"MSFT", value:"MS11-035");

  script_name(english:"MS11-035: Vulnerability in WINS Could Allow Remote Code Execution (2524426) (uncredentialed check)");
  script_summary(english:"Checks uninitialized memory returned in the WINS packet for a known return address.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Windows Internet Name Service (WINS)."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WINS (Windows Internet Name Service) installed on the
remote Windows host is affected by a memory corruption vulnerability
due to a logic error when handling a socket send exception. 

By sending specially crafted packets to the affected WINS system, a
remote attacker can potentially exploit this issue to execute  
arbitrary code as either SYSTEM on Windows 2003 or Local Service on
Windows 2008 / 2008 R2.   

Note that WINS is not installed by default on any of the affected
operating systems, although Nessus has determined it is on this host.

Note also that this plugin only checks for the vulnerability in
Windows 2003."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-11-167/");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2 :

http://technet.microsoft.com/en-us/security/bulletin/ms11-035"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("wins_detect.nasl", "os_fingerprint.nasl");
  script_require_ports(42);
  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");

port = get_service(svc:'wins', default:42, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

s = open_sock_tcp(port);
if (!s) exit(0, "Can't open a socket on port "+port+".");

os = get_kb_item("Host/OS");
if (!isnull(os) && '2003' >!< os)
  exit(1, "This plugin only detects vulnerable installations of Windows 2003.");

# Build a request that's missing padding
request = mkdword(0x00007800) + # opcode (supposed to be 0)
          mkdword(0x00000000) + # context (0 for the first packet)
          mkdword(0x00000000) + # message type (start_association = 0)
          mkdword(0x00000040) + # context (will be echoed back)
          mkword(0x0002) + # minor version
          mkword(0x0005);  # major version
          # There should be padding up to 0x29 bytes here (0x15 bytes)
          # The patched version checks for padding, unpatched doesn't
# Length
request = mkdword(strlen(request)) + request;

# Send the initial request and see if it fails
send(socket:s, data:request);
r = recv(socket:s, length:0xFFFF);
if (isnull(r)) patched = TRUE;
else patched = FALSE;

# Just to make sure the server's actually responding, send a second (valid)
# request that both patched and unpatched responds to
request = mkdword(0x00007800) + # opcode (supposed to be 0)
          mkdword(0x00000000) + # context (0 for the first packet)
          mkdword(0x00000000) + # message type (start_association = 0)
          mkdword(0x00000012) + # context (will be echoed back)
          mkword(0x0002) + # minor version
          mkword(0x0005) + # major version
          crap(length:0x15); # proper padding
# Length
request = mkdword(strlen(request)) + request;
send(socket:s, data:request);
r = recv(socket:s, length:0xFFFF);
if (isnull(r)) exit(1, "The server on port "+port+" failed to respond.");

# Make sure we're seeing the correct response and not a delayed response to
# the first message
context = getdword(blob:r, pos:8);
if (context != 0x00000012)
  exit(1, "The server on port "+port+" returned an unexpected response.");


# Clean up the connection
request = mkdword(0x00007800) + # opcode (supposed to be 0)
          mkdword(0x00000040) + # context
          mkdword(0x00000002) + # message type (stop_association = 2)
          mkdword(0x00000000) + # stop reason (0 = normal, 4 = error)
          crap(length:0x18); # padding
request = mkdword(strlen(request)) + request;
send(socket:s, data:request);
close(s);

if (!patched)
{
  security_hole(port);
  exit(0);
}
else exit(0, "The WINS server on port "+port+" is not affected.");
