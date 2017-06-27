#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10203);
 script_version ("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_cve_id("CVE-1999-0618");
 script_osvdb_id(9721);

 script_name(english:"rexecd Service Detection");
 script_summary(english:"Checks for the presence of rexecd.");

 script_set_attribute(attribute:"synopsis", value:
"The rexecd service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The rexecd service is running on the remote host. This service is
design to allow users of a network to execute commands remotely.
However, rexecd does not provide any good means of authentication, so
it may be abused by an attacker to scan a third-party host.");
 script_set_attribute(attribute:"solution", value:
"Comment out the 'exec' line in /etc/inetd.conf and restart the inetd
process." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value: "1999/06/07");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/31");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rexecd", 512);

 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/rexecd");

if(!port)
{
  port = 512;
  if (! service_is_unknown(port: port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
}

if(! get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

# This script will probably not work without credentials

cmd = strcat( "0", '\0',     # No separate channel for stderr
              "root", '\0',  # username
              "FOOBAR", '\0',# password
              "id", '\0' );  # command

send(socket:soc, data: cmd);
r = recv_line(socket:soc, length:4096);
close(soc);

if (strlen(r) == 0 || ord(r[0]) != 1) audit(AUDIT_NOT_DETECT, "REXECD", port);

if ( service_is_unknown ( port: port ) )
  register_service(port:port, proto:"rexecd");

pci_report = 'The remote REXECD service on port ' + port + ' accepts cleartext logins.';
set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
security_hole(port);
