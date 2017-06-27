#
# This script was written by Pasi Eronen <pasi.eronen@nixu.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
#  - Description
#  - Extract and display the load and the hostname
#  - Title revision, family change (9/17/09)


include("compat.inc");

if(description)
{
 script_id(10891);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_osvdb_id(735);

 script_name(english:"X Display Manager Control Protocol (XDMCP) Detection");
 script_summary(english:"Checks if XDM has the XDMCP protocol enabled.");

 script_set_attribute(attribute:"synopsis", value:
"The XDMCP service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The X Display Manager Control Protocol (XDMCP) service allows a Unix
user to remotely obtain a graphical X11 login and therefore act as a
local user on the remote host. If an attacker can gain a valid login
and password, this service could be used to gain further access on the
remote host. An attacker may also use this service to mount a
dictionary attack against the remote host to try to log in remotely.

Note that XDMCP is vulnerable to man-in-the-middle attacks, making it
easy for attackers to steal the credentials of legitimate users by
impersonating the XDMCP server. In addition to this, XDMCP is not a
ciphered protocol, which allows an attacker to capture the keystrokes
entered by the user.");
 script_set_attribute(attribute:"solution", value:
"Disable the XDMCP service, if you do not use it, and do not allow
this service to run across the Internet." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Pasi Eronen");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

#
# The script code starts here
#
function report(hostname, status)
{
  local_var report, pci_report;

  if ( hostname ) report += ' Hostname : ' + hostname + '\n';
  if ( status   ) report += ' Status   : ' + status + '\n';
 
  if ( report ) report = '\nUsing XDMCP, it was possible to obtain the following information\nabout the remote host :\n\n' + report + '\n';

  pci_report = 'The remote XDMCP service on port 177 accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/177", value:pci_report);

  security_warning(port:177, protocol:"udp", extra:report);
  register_service(port:177, proto:"xdmcp", ipproto:"udp");
  exit(0);
}

# this magic info request packet
req = raw_string(0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00);

if(!get_udp_port_state(177))
  audit(AUDIT_PORT_CLOSED, 177, "UDP");

soc = open_sock_udp(177);
if(!soc)
  audit(AUDIT_SOCK_FAIL, 177, "UDP");

send(socket:soc, data:req);
result  = recv(socket:soc, length:1000);

if (result &&
  strlen(result) > 3 &&
  ord(result[0]) == 0 &&
  ord(result[1]) == 1 &&
  ord(result[2]) == 0 &&
  ord(result[3]) == 5 )
{
  offset = 6;
  if ( strlen(result) <= offset ) report();
  len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
  offset += len;
  if ( strlen(result) <= offset ) report();
  len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
  if ( strlen(result) <= offset + len ) report();
  hostname = substr(result, offset, offset + len - 1);
  offset += len;
  if ( strlen(result) <= offset ) report(hostname:hostname);
  len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
  if ( strlen(result) < offset + len ) report(hostname:hostname);
  status = substr(result, offset, offset + len - 1);
  report(hostname:hostname, status:status);
}

audit(AUDIT_NOT_LISTEN, "XDMCP", 177, "UDP");
